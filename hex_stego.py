"""
hex_stego_fixed.py
==================
Fixed implementation of Hex-Level Steganography with AES-256.

WHY THE ORIGINAL BROKE IMAGES
──────────────────────────────
PNG stores pixel data as zlib-compressed bytes (IDAT chunks).
Randomly overwriting bytes inside compressed data corrupts the
decompressor and invalidates chunk CRCs → image unrenderable.

Even for BMP, replacing the UPPER nibble of pixel bytes causes
colour shifts of up to 240/255 — very visible.

THE FIX
───────
• BMP  → embed into the LOWER nibble of pixel bytes only.
          Max change per channel: 15/255 ≈ 6%  (imperceptible).
• PNG  → decode pixels with Pillow, embed into LSBs of pixel
          bytes, re-encode.  Max change: 1/255 — truly invisible.

PSNR is now computed on *decoded pixel arrays*, not raw file bytes,
which is the correct, standard definition.
"""

import os
import sys
import struct
import secrets
import argparse
import math

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import io


# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH        = 32          # 256-bit
IV_LENGTH         = 16          # AES block
FIXED_SALT        = b"HexStego_AES256_SALT_v1"


# ─────────────────────────────────────────────
#  AES-256-CBC  ENCRYPTION / DECRYPTION
# ─────────────────────────────────────────────
def derive_key(password: str) -> bytes:
    return PBKDF2(password.encode(), FIXED_SALT,
                  dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS,
                  hmac_hash_module=SHA256)

def encrypt_message(plaintext: str, password: str) -> bytes:
    """Returns IV || Ciphertext."""
    key = derive_key(password)
    iv  = secrets.token_bytes(IV_LENGTH)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def decrypt_message(iv_cipher: bytes, password: str) -> str:
    key = derive_key(password)
    iv, ct = iv_cipher[:IV_LENGTH], iv_cipher[IV_LENGTH:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


# ─────────────────────────────────────────────
#  BMP HELPERS  (raw pixel embed, lower nibble)
# ─────────────────────────────────────────────
def _bmp_pixel_offset(data: bytes) -> int:
    """Return byte offset where pixel data begins (from BMP file header)."""
    # Bytes 10-13 in BMP header = pixel data offset
    return struct.unpack_from("<I", data, 10)[0]

def _embed_bmp(cover_bytes: bytes, hex_cipher: str) -> bytes:
    """
    Embed hex_cipher into the lower nibble of BMP pixel bytes.
    Lower nibble change = max ±15 per channel → ~6% shift → imperceptible.
    """
    px_start = _bmp_pixel_offset(cover_bytes)
    data = bytearray(cover_bytes)
    available = len(data) - px_start

    L_h = len(hex_cipher)
    if L_h > available:
        raise ValueError(
            f"Image too small. Need {L_h} pixel bytes, have {available}."
        )

    for i, hc in enumerate(hex_cipher):
        nibble = int(hc, 16)          # 0-15
        byte_idx = px_start + i
        # Clear lower nibble, set new nibble
        data[byte_idx] = (data[byte_idx] & 0xF0) | nibble

    return bytes(data)

def _extract_bmp(stego_bytes: bytes, L_h: int) -> str:
    px_start = _bmp_pixel_offset(stego_bytes)
    chars = []
    for i in range(L_h):
        nibble = stego_bytes[px_start + i] & 0x0F
        chars.append(format(nibble, 'X'))
    return "".join(chars)


# ─────────────────────────────────────────────
#  PNG HELPERS  (LSB of pixel channels)
# ─────────────────────────────────────────────
def _embed_png(cover_bytes: bytes, hex_cipher: str) -> bytes:
    """
    Decode PNG pixels, embed each hex char's 4 bits across 4 pixel LSBs,
    then re-encode as PNG.  Max change per channel: 1/255 — invisible.
    """
    img = Image.open(io.BytesIO(cover_bytes)).convert("RGB")
    pixels = list(img.tobytes())           # flat list of R,G,B bytes

    # Each hex char = 4 bits → spread across 4 consecutive channel LSBs
    bits_needed = len(hex_cipher) * 4
    if bits_needed > len(pixels):
        raise ValueError(
            f"Image too small. Need {bits_needed} channel bytes, have {len(pixels)}."
        )

    idx = 0
    for hc in hex_cipher:
        nibble = int(hc, 16)              # 4 bits: b3 b2 b1 b0
        for bit_pos in range(3, -1, -1):  # b3 first
            bit = (nibble >> bit_pos) & 1
            pixels[idx] = (pixels[idx] & 0xFE) | bit
            idx += 1

    out_img = Image.frombytes("RGB", img.size, bytes(pixels))
    buf = io.BytesIO()
    out_img.save(buf, format="PNG")
    return buf.getvalue()

def _extract_png(stego_bytes: bytes, L_h: int) -> str:
    img = Image.open(io.BytesIO(stego_bytes)).convert("RGB")
    pixels = list(img.tobytes())

    chars = []
    idx = 0
    for _ in range(L_h):
        nibble = 0
        for bit_pos in range(3, -1, -1):
            bit = pixels[idx] & 1
            nibble = (nibble << 1) | bit
            idx += 1
        chars.append(format(nibble, 'X'))
    return "".join(chars)


# ─────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────
def embed(cover_path: str, message: str, password: str, output_path: str) -> int:
    """
    Encrypt `message` and embed into cover image.
    Supports PNG (LSB pixel embed) and BMP (lower-nibble embed).
    Returns L_h — the hex length needed for extraction.
    """
    ext = os.path.splitext(cover_path)[1].lower()
    if ext not in (".png", ".bmp"):
        raise ValueError("Only .png and .bmp are supported (lossless formats).")

    raw_cipher = encrypt_message(message, password)
    hex_cipher = raw_cipher.hex().upper()
    L_h = len(hex_cipher)

    with open(cover_path, "rb") as f:
        cover_bytes = f.read()

    if ext == ".bmp":
        stego_bytes = _embed_bmp(cover_bytes, hex_cipher)
    else:
        stego_bytes = _embed_png(cover_bytes, hex_cipher)

    with open(output_path, "wb") as f:
        f.write(stego_bytes)

    return L_h


def extract(stego_path: str, password: str, L_h: int) -> str:
    """Recover and decrypt the hidden message from a stego image."""
    ext = os.path.splitext(stego_path)[1].lower()
    if ext not in (".png", ".bmp"):
        raise ValueError("Only .png and .bmp are supported.")

    with open(stego_path, "rb") as f:
        stego_bytes = f.read()

    if ext == ".bmp":
        hex_cipher = _extract_bmp(stego_bytes, L_h)
    else:
        hex_cipher = _extract_png(stego_bytes, L_h)

    return decrypt_message(bytes.fromhex(hex_cipher), password)


# ─────────────────────────────────────────────
#  PSNR  (computed on decoded pixels — correct)
# ─────────────────────────────────────────────
def compute_psnr(original_path: str, stego_path: str) -> float:
    """
    PSNR on decoded pixel arrays — the standard, meaningful definition.
    PSNR = 10 * log10(255² / MSE)
    where MSE = mean((orig_pixels - stego_pixels)²).
    """
    orig  = list(Image.open(original_path).convert("RGB").tobytes())
    stego = list(Image.open(stego_path).convert("RGB").tobytes())

    if len(orig) != len(stego):
        raise ValueError("Images have different dimensions.")

    mse = sum((a - b) ** 2 for a, b in zip(orig, stego)) / len(orig)
    if mse == 0:
        return float("inf")
    return 10 * math.log10(255 ** 2 / mse)


def compute_capacity(image_path: str) -> dict:
    ext = os.path.splitext(image_path)[1].lower()
    if ext == ".bmp":
        with open(image_path, "rb") as f:
            data = f.read()
        px_start    = _bmp_pixel_offset(data)
        usable_bytes = len(data) - px_start
        # Each pixel byte holds 1 hex nibble → usable_bytes hex chars → usable_bytes/2 cipher bytes
        max_cipher  = usable_bytes // 2
    else:
        img = Image.open(image_path).convert("RGB")
        total_channels = img.size[0] * img.size[1] * 3
        # 4 channels per hex char
        max_cipher = total_channels // 4 // 2   # /4 channels per char, /2 = cipher bytes

    max_plain = max(0, max_cipher - IV_LENGTH - AES.block_size)
    return {
        "image"            : os.path.basename(image_path),
        "max_cipher_bytes" : max_cipher,
        "max_plaintext_bytes": max_plain,
        "max_plaintext_kb" : round(max_plain / 1024, 2),
    }


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Hex-Level Steganography + AES-256  (fixed: images stay intact)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("embed", help="Hide an encrypted message in an image")
    pe.add_argument("image");    pe.add_argument("output")
    pe.add_argument("message");  pe.add_argument("password")
    pe.add_argument("--psnr", action="store_true")

    px = sub.add_parser("extract", help="Recover a hidden message")
    px.add_argument("image");    px.add_argument("lh", type=int)
    px.add_argument("password")

    pc = sub.add_parser("capacity", help="Show max message size for an image")
    pc.add_argument("image")

    args = parser.parse_args()
    try:
        if args.cmd == "embed":
            L_h = embed(args.image, args.message, args.password, args.output)
            print(f"✅ Embedded!  L_h = {L_h}  (share this with the receiver)")
            if args.psnr:
                p = compute_psnr(args.image, args.output)
                print(f"   PSNR = {p:.2f} dB  (>50 dB = imperceptible)")
        elif args.cmd == "extract":
            msg = extract(args.image, args.password, args.lh)
            print(f"✅ Recovered: {msg!r}")
        elif args.cmd == "capacity":
            c = compute_capacity(args.image)
            print(f"Max plaintext: {c['max_plaintext_bytes']:,} bytes  ({c['max_plaintext_kb']} KB)")
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()
