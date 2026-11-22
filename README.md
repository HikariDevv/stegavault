# stegavault

[![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat-square)](https://openjdk.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen?style=flat-square)](#build)
[![Cipher](https://img.shields.io/badge/Cipher-AES--256--GCM-blue?style=flat-square)](#security-design)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](LICENSE)

Zero-dependency Java CLI for hiding **AES-256-GCM** encrypted files and text messages inside **PNG** images using **LSB (Least Significant Bit) steganography**.

```text
$ java -jar dist/stegavault.jar hide cover.png secret.pdf vault.png --password "correct horse battery staple"
Hidden successfully
  Cover      : cover.png (1920x1080)
  Output     : vault.png
  Mode       : File (secret.pdf)
  Cipher     : AES-256-GCM + PBKDF2-HMAC-SHA256 (200000 iter)
  Envelope   : 48.12 KB (compressed) [6.34% of 759.38 KB]
  SHA-256    : 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  Time       : 64.2 ms
```

## Features

- **Authenticated Encryption**: `AES/GCM/NoPadding` with a 256-bit key, random 12-byte IV, 128-bit authentication tag, and AAD-bound envelope header.
- **Strong Key Derivation**: `PBKDF2WithHmacSHA256` with `200,000` iterations and a fresh 16-byte `SecureRandom` salt per image.
- **Hidden Metadata**: Original filename, payload type, and size are encrypted inside the ciphertext rather than stored in plaintext.
- **Adaptive Compression**: Automatically compresses payloads with Deflate when it reduces size, maximizing image capacity.
- **Lossless PNG Output**: Embeds 3 bits per pixel across RGB least significant bits while preserving alpha channels (`ARGB`) when present.
- **Interactive Password Prompt**: Prompts securely via `System.console()` when `--password` is omitted so secrets stay out of shell history.
- **Path Traversal Protection**: Sanitizes recovered filenames and refuses to overwrite existing files unless `--force` is passed.

## Security Design

| Layer | Implementation |
| --- | --- |
| Key Derivation | `PBKDF2WithHmacSHA256`, 200,000 iterations, 16-byte random salt |
| Cipher | `AES-256-GCM`, 12-byte random IV, 128-bit auth tag |
| Header Integrity | Envelope header (`STGV`, version, flags, salt, IV) bound as GCM AAD |
| Embedding | 3 bits/pixel across R, G, B LSBs (`width * height * 3 / 8` bytes) |
| Compression | Optional Deflate before encryption (disabled with `--no-compress`) |

## Build

Requires **JDK 17+**. No Maven, Gradle, or external libraries needed.

**Windows (PowerShell):**
```powershell
javac --release 17 -d out src\com\dips\stegavault\*.java
mkdir dist -Force | Out-Null
jar cfe dist\stegavault.jar com.dips.stegavault.Main -C out .
```

**Linux / macOS:**
```bash
javac --release 17 -d out src/com/dips/stegavault/*.java
mkdir -p dist
jar cfe dist/stegavault.jar com.dips.stegavault.Main -C out .
```

## Usage

### Hide a file inside an image
```bash
java -jar dist/stegavault.jar hide cover.png secret.zip output.png
```

### Hide a text message
```bash
java -jar dist/stegavault.jar hide cover.png --text "meet at 21:00" output.png
```

### Extract a file or message
```bash
java -jar dist/stegavault.jar extract output.png ./recovered
```

### Inspect capacity and detect a vault header
```bash
java -jar dist/stegavault.jar info output.png
```

### Options

| Flag | Description |
| --- | --- |
| `-p, --password <pass>` | Supply password via CLI (omit to prompt interactively) |
| `-t, --text "<msg>"` | Embed a UTF-8 text message instead of a file |
| `--no-compress` | Store payload without Deflate compression |
| `-f, --force` | Overwrite existing file during extraction |
| `--no-color` | Disable ANSI terminal colors |

## Project Structure

```text
stegavault/
└── src/com/dips/stegavault/
    ├── Main.java          CLI commands, argument parsing, and safe file I/O
    ├── CryptoEngine.java  PBKDF2-HMAC-SHA256 key derivation and AES-256-GCM
    ├── PayloadCodec.java  Binary envelope framing, AAD binding, and Deflate
    ├── LsbStego.java      RGB/ARGB least-significant-bit embedding & extraction
    └── ConsoleUi.java     ANSI formatting, byte formatting, and password prompt
```

## License

MIT
