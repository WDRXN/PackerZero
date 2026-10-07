# PackerZero v1.0

Legitimate PE packer / protector for **PE32+ (x64) EXE and DLL** files.
LZ4-compresses the image, encrypts it with **AES-256-GCM** (Windows CNG),
embeds it in the runtime stub's last section, and runs it entirely from
memory — the original image bytes are never written to disk at runtime.

> **Scope note.** This is a software protector for your own binaries, CTF
> challenges, or authorized engagements. It is *not* a stealth tool: packed
> binaries are a textbook AV/EDR heuristic, the payload section is
> high-entropy by design, and nothing here is engineered to defeat
> detection, sandboxing, or analysis. Do not use it to obscure malware.

## Layout

```
PackerZero/
├── packer.py        # CLI packer (pure Python; optional 'cryptography' backend)
├── stub/stub.c      # x64 runtime stub source (no CRT; Win32 + CNG)
├── build.bat        # one-command stub build (MSVC or MinGW-w64)
├── README.md
└── MANIFEST.meta
```

**License: All rights reserved.** This repository contains no
LICENSE file. The code is the author's private work and may not
be copied, redistributed, or used without explicit written
permission.

## Quick start

1. **Build the stub** (once):
   ```bat
   build.bat
   ```
   Produces `stub\stub_exe.exe` and `stub\stub_dll.dll`.
   Needs MSVC (run from an "x64 Native Tools Command Prompt") or MinGW-w64.

2. **Validate the packer side** (no packed output is ever executed):
   ```bat
   python packer.py selftest
   ```

3. **Pack a binary**:
   ```bat
   python packer.py pack myapp.exe  myapp.packed.exe
   python packer.py pack mylib.dll  mylib.packed.dll  --password "{{PASSWORD}}"
   python packer.py pack myapp.exe  myapp.raw.exe    --no-compress
   ```

4. **Verify without executing** (authenticates + CRC-checks the payload):
   ```bat
   python packer.py verify myapp.packed.exe
   ```

The stub binaries must sit next to `packer.py` (or in `stub/`), or pass
`--stub <path>`.

## Crypto backend

The packer uses AES-256-GCM with automatic backend selection:

1. **`cryptography` package** (optional, `pip install cryptography`) —
   preferred; also covers sandboxed environments where Windows CNG
   disables AEAD modes.
2. **Windows CNG (`bcrypt.dll`)** via ctypes — zero-dependency fallback.

AES-GCM is a standard algorithm, so output from either backend is
interoperable: the runtime stub always decrypts via CNG on the target
machine. PBKDF2-SHA256 (200,000 iterations) follows the same backend
selection. `selftest` validates the active backend against NIST
SP 800-38D known-answer vectors.

## How it works

**Pack time (`packer.py`)**
1. Parse the target PE32+; refuse managed (.NET) images and non-AMD64
   binaries; warn about TLS callbacks and delay imports (unsupported).
2. LZ4-compress the raw image bytes (only if it actually shrinks).
3. AES-256-GCM encrypt. Key: random, or PBKDF2-SHA256 (200k iters) from
   `--password`. AAD = 116-byte header with the tag field zeroed.
4. Append `header + [password section] + ciphertext` into the stub's last
   section (raw data), and fix `VirtualSize`, `SizeOfRawData`,
   `SizeOfImage`, and the `MEM_READ` flag in the stub's headers.

**Run time (`stub.c`)**
1. Locate the overlay inside its own image (magic scan + sanity checks).
2. Rebuild the key (`keyXor ^ keyPad`, or PBKDF2 from the embedded
   password), AES-256-GCM decrypt, aborting on tag failure.
3. LZ4-decompress; verify CRC32 of the original image.
4. Map the image: allocate at the preferred base (fall back anywhere),
   copy headers + sections, apply `DIR64`/`HIGHLOW` relocations, resolve
   the import table via `LoadLibraryA`/`GetProcAddress`, then set the
   original section protections.
5. EXE: call the original entry point. DLL: call its `DllMain` and forward
   subsequent reasons.

## Honest limitations

- **Detection:** packing raises, not lowers, suspicion. High-entropy
  sections + a stub that allocates RWX memory are canonical AV/EDR
  triggers. Treat packed output as *flagged by default*.
- **Password key is embedded** in the output (obfuscated with a random
  pad). It protects against casual inspection only — a determined
  reverser recovers it. This is obfuscation, not cryptographic access
  control.
- **x64 only.** x86/ARM64 need their own stub builds.
- **Unsupported payload features:** .NET/managed images (refused), TLS
  callbacks and delay imports (warned, not resolved), bound imports
  (treated as unbound), exception directories beyond what the OS handles,
  and any feature requiring the OS loader (e.g., activation context,
  SxS). If a packed app misbehaves, check these first.
- **Loader lock:** the DLL stub resolves imports during `DLL_PROCESS_ATTACH`,
  which is technically loader-lock territory; it works in practice but is
  not guaranteed for every dependency chain.
- Stub binaries are **not signed** — they may be blocked or warned about
  on their own.

## Security notes

- Nothing auto-executes. `pack` and `verify` never run the payload; only
  `selftest` runs code, and only its own round-trip checks.
- Test packed output in an isolated VM/lab before distributing.
- The stub uses `PAGE_READWRITE` during mapping and restores per-section
  protections afterwards; there is no RWX region left mapped at rest.

## MITRE-style mapping (for defenders / emulation docs)

Packer behavior corresponds to: compression+encryption of payload
(T1027 / T1140), in-memory execution without disk artifacts (T1055-class
load behavior), and a custom loader performing import resolution. Use this
only to build detections, not to ship malware.

## Building the stub manually

MSVC (x64 Native Tools prompt):
```bat
cl /nologo /O2 /GS- /Gy /NODEFAULTLIB /entry:StubEntry /link /SUBSYSTEM:WINDOWS /NODEFAULTLIB kernel32.lib bcrypt.lib /OUT:stub\stub_exe.exe stub\stub.c
cl /nologo /O2 /GS- /Gy /NODEFAULTLIB /DSTUB_DLL /entry:DllMainStub /link /SUBSYSTEM:WINDOWS /DLL /NODEFAULTLIB kernel32.lib bcrypt.lib /OUT:stub\stub_dll.dll stub\stub.c
```

MinGW-w64:
```bat
x86_64-w64-mingw32-gcc -O2 -nostdlib -fno-stack-protector -o stub\stub_exe.exe stub\stub.c -Wl,--entry=StubEntry -lkernel32 -lbcrypt -lgcc
x86_64-w64-mingw32-gcc -O2 -nostdlib -fno-stack-protector -shared -DSTUB_DLL -o stub\stub_dll.dll stub\stub.c -Wl,--entry=DllMainStub -lkernel32 -lbcrypt -lgcc
```

## Copyright

© 2026 WDRXN. **All rights reserved.**

No license is granted. This software may not be used, copied, modified,
distributed, or incorporated into other work — in whole or in part — without
explicit written permission from the author.