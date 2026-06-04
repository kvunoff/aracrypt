# AraCrypt

**PE Encryptor for Linux** — encrypts Windows Portable Executable (`.exe`) files
into self-decrypting containers.

AraCrypt is a Rust reimplementation of [Hyperion](https://nullsecurity.net/tools/crypter.html)
by Christian Ammann (nullsecurity team), ported to run natively on Linux. It
encrypts 32-bit and 64-bit Windows PE executables using AES-128 in ECB mode.
The output is a self-contained `.exe` that brute-forces the decryption key at
startup, loads the original PE entirely in memory, and executes it — no file
ever touches disk.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Command-Line Options](#command-line-options)
- [Examples](#examples)
- [Architecture](#architecture)
- [Output Format](#output-format)
- [Limitations](#limitations)
- [Credits & License](#credits--license)

---

## How It Works

AraCrypt takes three stages to produce an encrypted executable:

### Stage 1 — Analyze
Parses the input PE file: verifies MZ and PE signatures, determines 32-bit or
64-bit, reads `ImageBase` and `SizeOfImage`, detects GUI vs console subsystem,
and refuses to encrypt DLLs or .NET assemblies.

### Stage 2 — Encrypt & Generate
Generates a random AES-128 key of configurable length and character range.
Computes an additive byte checksum of the original PE. Prepends the checksum,
pads to an AES block boundary, and encrypts the entire blob with AES-128-ECB
using the [RustCrypto `aes` crate](https://crates.io/crates/aes).

The encrypted bytes are written as a flat assembler (FASM) `db` array into
intermediate `.inc` files. Other `.inc` files carry PE parameters (`ImageBase`,
`SizeOfImage`, key length, key range) consumed by the runtime loader.

### Stage 3 — Compile
Invokes [FASM](https://flatassembler.net) (flat assembler) to assemble the
runtime loader together with the generated `.inc` files into the final
self-decrypting `.exe`.

### At Runtime (on Windows)
1. Optionally creates `log.txt` for debugging.
2. Brute-forces the AES key by iterating over the entire key space. Each
   candidate key is tried: decrypt the blob, verify the checksum. If it
   matches, the key is found.
3. Copies the decrypted PE into memory at the original `ImageBase`.
4. Resolves the import table (loads required DLLs and APIs).
5. Sets memory protection per section (`PAGE_EXECUTE_READ`, etc.).
6. Jumps to the original entry point.

**No temporary files — the original executable is never written to disk.**

---

## Requirements

- **Rust** toolchain (1.70+ recommended) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **FASM** (flat assembler) — required to compile the self-decrypting loader

| Distribution | Install command |
|---|---|
| **Arch Linux** | `sudo pacman -S fasm` |
| **Debian / Ubuntu** | `sudo apt install fasm` |
| **Fedora** | `sudo dnf install fasm` |
| **openSUSE** | `sudo zypper install fasm` |
| **Manual** | Download from [flatassembler.net](https://flatassembler.net) |

---

## Installation

### Arch Linux (AUR)

```bash
yay -S aracrypt
```

### From Source

```bash
git clone https://github.com/kvunoff/aracrypt.git
cd aracrypt
cargo build --release

# Install system-wide (optional)
sudo cp target/release/AraCrypt /usr/local/bin/aracrypt
```

---

## Usage

```
aracrypt [OPTIONS] <INPUT> <OUTPUT>
```

Run `aracrypt --help` for the full help message.

---

## Command-Line Options

| Flag | Argument | Description | Default |
|---|---|---|---|
| `-k`, `--key-length` | `1..16` | AES key length in bytes. Longer keys mean exponentially more brute-force attempts at runtime. | `6` |
| `-s`, `--key-space` | `2..255` | Value range for each key byte (0 to N−1). Total keys to brute-force = **keySpace^keyLength**. | `4` |
| `-l`, `--logfile` | — | Include debug logging code in the output. Generates `log.txt` at runtime on Windows. | off |
| `-v`, `--verbose` | — | Print detailed status output including the generated AES key, intermediate file names, and FASM compiler output. | off |
| `-h`, `--help` | — | Print help. | — |
| `-V`, `--version` | — | Print version. | — |

### Understanding Key Space

The total number of brute-force attempts = **keySpace^keyLength**.

| Key Length | Key Space | Total Attempts | Example Runtime |
|---|---|---|---|
| 3 | 3 | 27 | Instant |
| 4 | 4 | 256 | < 1 second |
| 6 | 4 | 4,096 | Seconds |
| 8 | 6 | 1,679,616 | Minutes |
| 10 | 10 | 10,000,000,000 | Impractical |

Choose values that balance security and startup delay.

---

## Examples

### Basic Encryption

```bash
aracrypt myapp.exe myapp_encrypted.exe
```

Output:
```
[*] Analyzing input file: myapp.exe
[+] Found 64-bit PE, ImageBase: 0x140000000, SizeOfImage: 0x2cd000, Subsystem: GUI
[*] Encrypting with AES-128-ECB (key: 6 bytes, space: 4 values)...
[+] Checksum: 0x0d884610
[+] Original data: 3233105 bytes | Encrypted: 3233120 bytes (padded to AES block)
[*] Generating self-decrypting loader...
[*] Compiling with FASM...
[+] Final executable: myapp_encrypted.exe (3240960 bytes)
```

### Fast Key (Quicker Startup, Weaker Obfuscation)

```bash
aracrypt -k 3 -s 3 myapp.exe fast.exe
```

3 bytes × 3 values = 27 brute-force attempts. The output starts almost instantly.

### With Runtime Logging

```bash
aracrypt -l myapp.exe logged.exe
```

The output will create `log.txt` on the target Windows machine, logging the
brute-force progress and PE loading steps. Useful for debugging.

### Verbose Mode

```bash
aracrypt -v myapp.exe out.exe
```

Shows the generated AES key, each intermediate `.inc` / `.asm` file written,
and the full FASM compiler output (pass count, memory used, output size).

### All Options Combined

```bash
aracrypt -k 8 -s 5 -l -v input.exe output.exe
```

8-byte key, 5 values per byte, with logfile enabled, verbose output.

---

## Architecture

```
aracrypt/
├── Cargo.toml                 # Rust project manifest
├── src/
│   ├── main.rs                # CLI (clap), orchestration of 3 stages
│   ├── pe.rs                  # PE header parsing (MZ/PE signatures, ImageBase,
│   │                          #   SizeOfImage, GUI/console, .NET detection)
│   ├── crypto.rs              # AES-128-ECB encryption, additive checksum,
│   │                          #   random key generation
│   └── fasm.rs                # FASM .inc/.asm file generation,
│                              #   FASM subprocess invocation
├── stub/
│   ├── Container/
│   │   ├── 32/                # 32-bit FASM runtime loader
│   │   │   ├── main.asm           Entry point + orchestration
│   │   │   ├── loadexecutable.asm PE loader (sections, imports, permissions)
│   │   │   ├── loadapis.asm       Dynamic API resolution
│   │   │   ├── logfile_enable.asm Debug logging implementation
│   │   │   ├── logfile_disable.asm Logging (no-op)
│   │   │   ├── pe.inc             PE format constants for FASM
│   │   │   ├── hyperion.inc       API table offsets
│   │   │   └── createstrings.inc  String creation macros
│   │   └── 64/                # 64-bit FASM runtime loader
│   │       ├── main.asm           Entry point + orchestration
│   │       ├── loadexecutable.asm PE loader (sections, imports, permissions)
│   │       ├── logfile_enable.asm Debug logging (64-bit)
│   │       ├── logfile_disable.asm Logging (no-op)
│   │       └── pe.inc             PE format constants
│   ├── Aes/
│   │   ├── 32/                # AES-128 implementation in 32-bit FASM
│   │   │   ├── aes.inc            Mode selection (AES-128)
│   │   │   ├── aes.asm            encAES / decAES procedures
│   │   │   ├── decryptexecutable.asm Brute-force decryption driver
│   │   │   ├── encryptionrounds.asm SubBytes / ShiftRows / MixColumns / AddRoundKey
│   │   │   ├── decryptionrounds.asm Inverse AES rounds
│   │   │   ├── keychain.asm       Round key expansion
│   │   │   ├── sbox.asm           S-Box table generation
│   │   │   ├── rcon.asm           Round constant table
│   │   │   └── galois.asm         Galois field multiplication tables
│   │   └── 64/                # AES-128 implementation in 64-bit FASM
│   │       └── ...                (mirrors 32-bit structure)
│   └── FASM_INCLUDE/          # Windows API constants and macros for FASM
│       ├── win32a.inc / win64a.inc    Top-level API includes
│       ├── equates/                  Windows API constant definitions
│       ├── macro/                    FASM macro library (proc, import, struct)
│       └── pcount/                   Parameter count helpers
```

### Data Flow

```
  Input .exe
      │
      ▼
  [pe.rs]  ─── Parse MZ/PE headers
      │         ImageBase, SizeOfImage, 32/64-bit, GUI/console
      │
      ▼
  [crypto.rs] ─── checksum + pad + AES-128-ECB encrypt
      │            Generate random key
      │
      ▼
  [fasm.rs]  ─── Write encrypted bytes as FASM db array
      │          Write .inc files (key_size, image_base, infile_size, ...)
      │          Write decryption_includes.asm, logfile_select.asm, main_prolog.inc
      │
      ▼
  FASM        ─── Assemble Container/main.asm + generated .inc files
      │            → Output .exe (self-decrypting container)
      │
      ▼
  Output .exe
```

### Generated Intermediate Files

During stage 2, the following files are generated in `stub/Container/{32|64}/`
and cleaned up after FASM compilation:

| File | Content |
|---|---|
| `main_prolog.inc` | `format PE64 GUI 5.0 at IMAGE_BASE` |
| `image_base.inc` | `IMAGE_BASE equ 0x140000000` |
| `image_size.inc` | `IMAGE_SIZE equ 0x2cd000` |
| `infile_array.inc` | `db 0xAB, 0xCD, ...` (encrypted PE as hex array) |
| `infile_size.inc` | `INFILE_SIZE equ 0x3153E0` |
| `key_size.inc` | `REAL_KEY_SIZE equ 0x6` / `REAL_KEY_RANGE equ 0x4` |
| `logfile_select.asm` | `include 'logfile_enable.asm'` or `include 'logfile_disable.asm'` |
| `decryption_includes.asm` | `include '../../Aes/64/aes.inc'` + aes.asm + decryptexecutable.asm |

---

## Output Format

AraCrypt uses colored prefixes to indicate message severity:

| Color | Prefix | Meaning |
|---|---|---|
| Blue | `[*]` | Status — progress update |
| Green | `[+]` | Success — a value or result |
| Red | `[!]` | Error — something went wrong |
| Gray | `    ` | Verbose detail (only with `-v`) |

---

## Limitations

- **Requires FASM.** The runtime loader is written in flat assembler
  and must be compiled by FASM at build time. Pre-compiled loaders are not
  bundled.

- **32-bit support is deprecated.** The 32-bit container is included but not
  actively tested. The original Hyperion deprecated 32-bit support in v2.3.

- **No .NET support.** .NET assemblies are detected (via the CLR Runtime Header
  in the DataDirectory) and rejected. Encrypting .NET executables requires a
  fundamentally different approach.

- **No DLL support.** The tool rejects DLLs (detected via `IMAGE_FILE_DLL` in
  the COFF characteristics).

- **Key space is limited by design.** Since the container brute-forces the AES
  key, the key must be small enough to be found in a reasonable time at
  startup. This is an obfuscation technique, not a strong encryption scheme.

- **Not a packer.** AraCrypt does not compress the input executable. The output
  is larger than the input due to the container stub overhead (~6–8 KB for the
  container, plus logfile code if `-l` is used).

- **Run from project root.** `aracrypt` expects the `stub/` directory to
  exist relative to the current working directory.

---

## Credits & License

AraCrypt is a Rust port of **Hyperion** by Christian Ammann (belial) of the
[nullsecurity team](https://nullsecurity.net).

- **Original Hyperion:** [nullsecurity.net/tools/crypter.html](https://nullsecurity.net/tools/crypter.html)
- **Paper:** *"Hyperion: Implementation of a PE-Crypter"* by Christian Ammann
- **FASM:** [flatassembler.net](https://flatassembler.net) by Tomasz Grysztar
- **FASM AES implementation:** [FasmAES](https://github.com/tyler569/fasm-aes)
  by Christian Ammann (BSD 2-Clause)
- **AES encryption (build-time):** [RustCrypto `aes`](https://crates.io/crates/aes)
  (MIT / Apache 2.0)

The FASM runtime loader and AES implementation are distributed under the **BSD
2-Clause License**. The AraCrypt Rust code is licensed under the **MIT License**.

---

**Disclaimer:** This tool is intended for educational purposes, security
research, and legitimate software protection. The authors are not responsible
for any misuse.
