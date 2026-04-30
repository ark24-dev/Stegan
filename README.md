# Hex-Level Steganography with AES-256

A Python tool for hiding encrypted messages inside image files. Combines **AES-256-CBC encryption** with **hex-level steganography** to provide two layers of security — the message is encrypted first, then hidden invisibly inside a PNG or BMP image.

Based on the paper:
> *"Steganography for Secure Data Communication using an Enhanced Encryption Algorithm"* — Garg, Rawat, Chauhan, Patial, Bhale (2026, IEEE)

---

## How It Works

```
Sender:   Plaintext → AES-256-CBC → Hex → Embed into image pixels
Receiver: Extract hex from image → Bytes → AES-256-CBC Decrypt → Plaintext
```

**Two-layer security:**
1. **Encryption** — AES-256-CBC with a key derived from your password via PBKDF2 (100,000 iterations). Even if someone finds the stego image, the message is encrypted.
2. **Steganography** — the encrypted data is hidden inside pixel bytes of the image. The image looks identical to the original.

**Embedding method by format:**

| Format | Method | Max pixel change | Typical PSNR |
|--------|--------|-----------------|--------------|
| PNG    | 1 bit per channel (LSB) | ±1 per channel | ~80 dB |
| BMP    | Lower nibble of pixel bytes | ±15 per channel | ~65 dB |

> **PSNR (Peak Signal-to-Noise Ratio)** measures image distortion. Values above 50 dB are considered imperceptible to the human eye. This tool achieves 65–80 dB — the stego image is visually identical to the original.

---

## Requirements

Python 3.8+ and two libraries:

```bash
pip install pycryptodome pillow
```

| Library | Purpose |
|---------|---------|
| `pycryptodome` | AES-256 encryption, PBKDF2 key derivation |
| `pillow` | PNG pixel decoding and re-encoding |

---

## Quick Start

```bash
# 1. Hide a message
python hex_stego_fixed.py embed cover.png stego.png "Your secret message" "your_password"

# 2. The terminal prints: L_h = 224  ← save this number
# 3. Share stego.png with the receiver (looks identical to cover.png)

# 4. Receiver recovers the message
python hex_stego_fixed.py extract stego.png 224 "your_password"
```

---

## Commands

### `embed` — Hide a message

```
python hex_stego_fixed.py embed <image> <output> <message> <password> [--psnr]
```

| Argument | Description |
|----------|-------------|
| `image` | Path to the original cover image (`.png` or `.bmp`) |
| `output` | Path to save the stego image |
| `message` | The secret text to hide |
| `password` | Encryption password |
| `--psnr` | (Optional) Print PSNR score after embedding |

**Example:**
```bash
python hex_stego_fixed.py embed photo.png secret_photo.png "Meet at noon" "hunter2" --psnr
```

**Output:**
```
✅ Embedded!  L_h = 192  (share this with the receiver)
   PSNR = 79.84 dB  (>50 dB = imperceptible)
```

> ⚠️ The `L_h` value printed after embedding is required for extraction. Transmit it to the receiver via a separate channel (e.g., text message, email). It is not sensitive on its own — only the password grants access to the message.

---

### `extract` — Recover a message

```
python hex_stego_fixed.py extract <image> <L_h> <password>
```

| Argument | Description |
|----------|-------------|
| `image` | Path to the stego image |
| `L_h` | Hex length value printed during embedding |
| `password` | Same password used during embedding |

**Example:**
```bash
python hex_stego_fixed.py extract secret_photo.png 192 "hunter2"
```

**Output:**
```
✅ Recovered: 'Meet at noon'
```

---

### `capacity` — Check how much a image can hold

```
python hex_stego_fixed.py capacity <image>
```

**Example:**
```bash
python hex_stego_fixed.py capacity photo.png
```

**Output:**
```
Max plaintext: 90,734 bytes  (88.61 KB)
```

---

## Usage Examples

### Basic message hiding (PNG)

```bash
python hex_stego_fixed.py embed landscape.png landscape_stego.png \
  "Coordinates: 37.7749° N, 122.4194° W" "SecretKey@99"
# → L_h = 208

python hex_stego_fixed.py extract landscape_stego.png 208 "SecretKey@99"
# → ✅ Recovered: 'Coordinates: 37.7749° N, 122.4194° W'
```

### Longer message (BMP)

```bash
python hex_stego_fixed.py capacity archive.bmp
# → Max plaintext: 245,231 bytes  (239.48 KB)

python hex_stego_fixed.py embed archive.bmp archive_stego.bmp \
  "$(cat classified_report.txt)" "p@ssw0rd_2026" --psnr
```

### Check quality after embedding

```bash
python hex_stego_fixed.py embed original.png stego.png "test" "pass" --psnr
# → PSNR = 80.12 dB  (>50 dB = imperceptible)
```

---

## Supported Formats

| Format | Supported | Notes |
|--------|-----------|-------|
| PNG    | ✅ Yes | Lossless. Embeds in pixel LSBs after decode/re-encode |
| BMP    | ✅ Yes | Lossless. Embeds in lower nibble of raw pixel bytes |
| JPEG   | ❌ No  | Lossy compression destroys embedded data on re-save |
| WEBP   | ❌ No  | Lossy by default |
| GIF    | ❌ No  | Palette-based, not suitable |

> **Why not JPEG?** JPEG compression intentionally alters byte values to reduce file size. Any bytes you embed get scrambled when the image is re-encoded. PNG and BMP are lossless — every byte you write stays exactly as written.

---

## Security Notes

**What an attacker needs to recover the message:**
1. The stego image
2. The password
3. The `L_h` value

Without the password, the message cannot be decrypted — AES-256 with a properly derived key provides 2²⁵⁶ possible keys, far beyond brute-force capability.

**Cryptographic details:**
- Key derivation: PBKDF2-HMAC-SHA256, 100,000 iterations
- Encryption: AES-256-CBC with a random IV per message
- Padding: PKCS7

**Known limitations:**
- `L_h` must be transmitted separately (not embedded in the image by default)
- The embedding start offset is fixed (predictable if the method is known)
- Byte-level forensic tools (entropy scanners) could potentially detect high-entropy regions
- Only lossless image formats are supported

---

## File Structure

```
hex_stego_fixed.py   ← everything in one file, no external config needed
```

### Key functions (for programmatic use)

```python
from hex_stego_fixed import embed, extract, compute_psnr, compute_capacity

# Embed
L_h = embed("cover.png", "secret message", "password", "stego.png")

# Extract
message = extract("stego.png", "password", L_h)

# Quality check
psnr = compute_psnr("cover.png", "stego.png")   # returns dB value

# Capacity
info = compute_capacity("cover.png")
# → { 'max_plaintext_bytes': 90734, 'max_plaintext_kb': 88.61, ... }
```

---

## Troubleshooting

**"Image too small" error**
The message (after encryption) is larger than the image can hold. Either use a larger image or a shorter message. Run `capacity` to check the limit.

**"Only .png and .bmp are supported" error**
Convert your image first:
```bash
# Using Python
python -c "from PIL import Image; Image.open('photo.jpg').save('photo.png')"
```

**Extraction returns garbage / raises an error**
Either the wrong password or the wrong `L_h` value was used. Make sure both match exactly what was used during embedding.

**PSNR seems low (< 50 dB)**
This can happen with very small images where the embedded data occupies a large fraction of the pixels. Use a larger cover image.

---

## License

MIT — free to use, modify, and distribute with attribution.
