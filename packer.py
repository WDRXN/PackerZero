#!/usr/bin/env python3
"""
PackerZero v1.0 - legitimate PE packer / protector
==================================================
Packs a PE32+ (x64) EXE or DLL: LZ4-compresses it, encrypts it with
AES-256-GCM (Windows CNG / bcrypt.dll), and appends it to the section
overlay of a small runtime stub. The stub decrypts in memory, verifies
CRC32 integrity, maps the original image (relocations + imports) and
transfers control to the original entry point. The original file bytes
never touch the disk at runtime.

Intended use: protecting YOUR OWN software, CTF challenges, or authorized
security engagements. This is a protector, NOT a stealth tool: packed
binaries are a classic AV/EDR heuristic and will very likely still be
flagged. Nothing here is designed to evade detection.

No third-party Python packages required (uses ctypes -> bcrypt.dll).

[Xyberix] - Protector Module - Requires Manual Build of stub first
"""

import argparse
import os
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# PE parsing (minimal, PE32+ only)
# ---------------------------------------------------------------------------

class PEError(Exception):
    pass


class PE:
    DIR_NAMES = {
        0: "export", 1: "import", 2: "resource", 3: "exception",
        5: "basereloc", 6: "debug", 9: "tls", 10: "loadcfg",
        11: "iat", 12: "delayimport", 13: "clr", 14: "res",
    }

    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEError("not a PE file (missing MZ)")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if self.e_lfanew + 24 > len(data) or data[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("bad PE signature")
        coff = self.e_lfanew + 4
        (self.machine, self.nsec, _ts, _sym, _nsym,
         self.opt_size, self.file_chars) = struct.unpack_from("<HHIIIHH", data, coff)
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        if self.magic != 0x20B:
            raise PEError(f"not PE32+ (magic={self.magic:#x}); only x64 images are supported")
        self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
        self.image_base = struct.unpack_from("<Q", data, self.opt + 24)[0]
        self.sect_align = struct.unpack_from("<I", data, self.opt + 32)[0]
        self.file_align = struct.unpack_from("<I", data, self.opt + 36)[0]
        self.size_of_image = struct.unpack_from("<I", data, self.opt + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
        self.num_rva = struct.unpack_from("<I", data, self.opt + 108)[0]
        self.dirs = []
        for i in range(self.num_rva):
            rva, size = struct.unpack_from("<II", data, self.opt + 112 + i * 8)
            self.dirs.append((rva, size))
        self.sections = []
        so = self.opt + self.opt_size
        for i in range(self.nsec):
            off = so + i * 40
            name = data[off:off + 8].rstrip(b"\x00")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append({
                "name": name, "vsize": vsize, "vaddr": vaddr,
                "rawsize": rawsize, "rawptr": rawptr, "chars": chars, "hdr_off": off,
            })

    @property
    def is_dll(self) -> bool:
        return bool(self.file_chars & 0x2000)

    def dir_rva(self, idx: int) -> int:
        return self.dirs[idx][0] if idx < len(self.dirs) else 0

    def check_support(self) -> list:
        """Return a list of warning strings; raise on hard blockers."""
        warns = []
        if self.machine != 0x8664:
            raise PEError(f"machine={self.machine:#x}: only AMD64 (0x8664) images are supported")
        if self.dir_rva(13):  # COM descriptor
            raise PEError("managed (.NET) image detected - cannot be memory-mapped by this stub")
        if self.dir_rva(12):  # delay imports
            warns.append("delay imports detected: they will NOT be resolved by the stub")
        if self.dir_rva(9):   # TLS
            warns.append("TLS directory detected: TLS callbacks will NOT run")
        if self.dir_rva(0):
            warns.append("image has exports (only relevant when packing DLLs)")
        return warns


def align_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


# ---------------------------------------------------------------------------
# LZ4 block codec (standard LZ4 block format, shared with the C stub)
# ---------------------------------------------------------------------------

def lz4_compress(data: bytes) -> bytes:
    """Minimal, correct LZ4 block compressor (hash-chain free, single probe)."""
    n = len(data)
    out = bytearray()
    HASH_BITS = 16
    HASH_SIZE = 1 << HASH_BITS
    M = 0xFFFFFFFF
    htab = [-1] * HASH_SIZE
    MINMATCH = 4
    WINDOW = 0xFFFF
    pos = 0
    anchor = 0

    def h4(i):
        return ((int.from_bytes(data[i:i + 4], "little") * 0x9E3779B1) & M) >> (32 - HASH_BITS)

    while pos < n - 3:
        h = h4(pos)
        cand = htab[h]
        htab[h] = pos
        if 0 <= cand >= anchor and (pos - cand) <= WINDOW:
            # verify match
            l = 0
            while l < n - pos and data[cand + l] == data[pos + l]:
                l += 1
            if l >= MINMATCH:
                lit = pos - anchor
                tok_pos = len(out)
                out.append(0)  # token placeholder
                if lit >= 15:
                    r = lit - 15
                    while r >= 255:
                        out.append(255)
                        r -= 255
                    out.append(r)
                out += data[anchor:pos]
                off = pos - cand
                out.append(off & 0xFF)
                out.append((off >> 8) & 0xFF)
                ml = l - MINMATCH
                if ml >= 15:
                    r = ml - 15
                    while r >= 255:
                        out.append(255)
                        r -= 255
                    out.append(r)
                out[tok_pos] = ((15 if lit >= 15 else lit) << 4) | (15 if ml >= 15 else ml)
                pos += l
                anchor = pos
                # re-hash positions inside long matches for better ratio
                for k in range(pos - l + 1, pos):
                    if k < n - 3:
                        htab[h4(k)] = k
                continue
        pos += 1

    # final literals
    lit = n - anchor
    tok_pos = len(out)
    out.append(0)
    if lit >= 15:
        r = lit - 15
        while r >= 255:
            out.append(255)
            r -= 255
        out.append(r)
    out += data[anchor:]
    out[tok_pos] = (15 if lit >= 15 else lit) << 4
    return bytes(out)


def lz4_decompress(src: bytes, dst_capacity: int) -> bytes:
    s = 0
    s_end = len(src)
    out = bytearray()
    while s < s_end:
        token = src[s]; s += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if s >= s_end:
                    raise ValueError("truncated literal extension")
                e = src[s]; s += 1
                lit_len += e
                if e != 255:
                    break
        if s_end - s < lit_len:
            raise ValueError("literal overruns input")
        out += src[s:s + lit_len]
        s += lit_len
        if s >= s_end:
            break
        if s_end - s < 2:
            raise ValueError("truncated offset")
        off = src[s] | (src[s + 1] << 8)
        s += 2
        if off == 0 or off > len(out):
            raise ValueError("bad match offset")
        match_len = token & 15
        if match_len == 15:
            while True:
                if s >= s_end:
                    raise ValueError("truncated match extension")
                e = src[s]; s += 1
                match_len += e
                if e != 255:
                    break
        match_len += 4
        if len(out) + match_len > dst_capacity:
            raise ValueError("output overflow")
        mstart = len(out) - off
        for i in range(match_len):
            out.append(out[mstart + i])
    if len(out) != dst_capacity:
        raise ValueError(f"size mismatch: got {len(out)}, expected {dst_capacity}")
    return bytes(out)


# ---------------------------------------------------------------------------
# AES-256-GCM + PBKDF2
# Backend priority:
#   1. `cryptography` package (AESGCM) - preferred, works everywhere
#   2. Windows CNG via ctypes (BCrypt) - fallback, no third-party deps
# AES-GCM is a standard algorithm, so ciphertext from either backend is
# interoperable: the C stub always decrypts via CNG at runtime. (Some
# sandboxed environments disable CNG AEAD modes; the `cryptography`
# backend covers that case at pack time.)
# ---------------------------------------------------------------------------

import ctypes
import ctypes.wintypes as wt

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False

_crypto_backend = "cryptography" if _HAVE_CRYPTOGRAPHY else "cng"

_bcrypt = ctypes.WinDLL("bcrypt.dll", use_last_error=True)


def _w(s: str) -> bytes:
    """BCrypt property names/values are UTF-16LE with NUL terminator."""
    return (s + "\x00").encode("utf-16-le")


class _AUTH_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.ULONG),
        ("dwInfoVersion", wt.ULONG),
        ("pbNonce", ctypes.c_void_p),
        ("cbNonce", wt.ULONG),
        ("pbAuthData", ctypes.c_void_p),
        ("cbAuthData", wt.ULONG),
        ("pbTag", ctypes.c_void_p),
        ("cbTag", wt.ULONG),
        ("pbMacContext", ctypes.c_void_p),
        ("cbMacContext", wt.ULONG),
    ]


BCRYPT_AUTH_MODE_INFO_VERSION = 1


def _open_alg(alg: str):
    h = wt.HANDLE()
    rc = _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h), _w(alg), None, 0)
    if rc < 0:
        raise OSError(f"BCryptOpenAlgorithmProvider({alg}) failed: {rc:#x}")
    return h


def _aes_key_handle(key: bytes):
    h_alg = _open_alg("AES")
    try:
        rc = _bcrypt.BCryptSetProperty(h_alg, _w("ChainingMode"),
                                           _w("ChainingModeGCM"),
                                           len(_w("ChainingModeGCM")), 0)
        if rc < 0:
            raise OSError(f"BCryptSetProperty(GCM) failed: {rc:#x}")
        obj_len = wt.ULONG(0)
        res = wt.ULONG(0)
        rc = _bcrypt.BCryptGetProperty(h_alg, _w("ObjectLength"),
                                           ctypes.byref(obj_len), 4,
                                           ctypes.byref(res), 0)
        if rc < 0:
            raise OSError(f"BCryptGetProperty(ObjectLength) failed: {rc:#x}")
        obj = ctypes.create_string_buffer(obj_len.value)
        h_key = wt.HANDLE()
        rc = _bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key),
                                                    obj, obj_len.value,
                                                    key, len(key), 0)
        if rc < 0:
            raise OSError(f"BCryptGenerateSymmetricKey failed: {rc:#x}")
        return h_alg, h_key
    except Exception:
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
        raise


def aes256gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes):
    """Returns (ciphertext, tag). Tag is always 16 bytes."""
    assert len(key) in (16, 24, 32) and len(nonce) == 12
    if _HAVE_CRYPTOGRAPHY:
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        return ct[:-16], ct[-16:]
    h_alg, h_key = _aes_key_handle(key)
    try:
        info = _AUTH_INFO()
        info.cbSize = ctypes.sizeof(_AUTH_INFO)
        info.dwInfoVersion = BCRYPT_AUTH_MODE_INFO_VERSION
        info.pbNonce = ctypes.cast(ctypes.create_string_buffer(nonce, len(nonce)), ctypes.c_void_p)
        info.cbNonce = len(nonce)
        info.pbAuthData = ctypes.cast(ctypes.create_string_buffer(aad, len(aad)), ctypes.c_void_p)
        info.cbAuthData = len(aad)
        tag = ctypes.create_string_buffer(16)
        info.pbTag = ctypes.cast(tag, ctypes.c_void_p)
        info.cbTag = 16
        out = ctypes.create_string_buffer(len(plaintext))
        out_len = wt.ULONG(0)
        rc = _bcrypt.BCryptEncrypt(h_key, plaintext, len(plaintext),
                                   ctypes.byref(info), None, 0,
                                   out, len(plaintext), ctypes.byref(out_len), 0)
        if rc < 0 or out_len.value != len(plaintext):
            raise OSError(f"BCryptEncrypt failed: {rc:#x}")
        return out.raw, tag.raw
    finally:
        _bcrypt.BCryptDestroyKey(h_key)
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def aes256gcm_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes):
    assert len(key) in (16, 24, 32) and len(nonce) == 12 and len(tag) == 16
    if _HAVE_CRYPTOGRAPHY:
        try:
            return AESGCM(key).decrypt(nonce, ct + tag, aad)
        except Exception:
            raise OSError("authentication failed (wrong key / corrupted payload)")
    h_alg, h_key = _aes_key_handle(key)
    try:
        info = _AUTH_INFO()
        info.cbSize = ctypes.sizeof(_AUTH_INFO)
        info.dwInfoVersion = BCRYPT_AUTH_MODE_INFO_VERSION
        info.pbNonce = ctypes.cast(ctypes.create_string_buffer(nonce, len(nonce)), ctypes.c_void_p)
        info.cbNonce = len(nonce)
        info.pbAuthData = ctypes.cast(ctypes.create_string_buffer(aad, len(aad)), ctypes.c_void_p)
        info.cbAuthData = len(aad)
        info.pbTag = ctypes.cast(ctypes.create_string_buffer(tag, len(tag)), ctypes.c_void_p)
        info.cbTag = len(tag)
        out = ctypes.create_string_buffer(len(ct))
        out_len = wt.ULONG(0)
        rc = _bcrypt.BCryptDecrypt(h_key, ct, len(ct), ctypes.byref(info),
                                   None, 0, out, len(ct), ctypes.byref(out_len), 0)
        if rc < 0 or out_len.value != len(ct):
            raise OSError("authentication failed (wrong key / corrupted payload)")
        return out.raw
    finally:
        _bcrypt.BCryptDestroyKey(h_key)
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    if _HAVE_CRYPTOGRAPHY:
        kdf = PBKDF2HMAC(hashes.SHA256(), length, salt, iterations)
        return kdf.derive(password)
    h_alg = _open_alg("PBKDF2")
    try:
        out = ctypes.create_string_buffer(length)
        rc = _bcrypt.BCryptDeriveKeyPBKDF2(h_alg, password, len(password),
                                           salt, len(salt), iterations,
                                           out, length, 0)
        if rc < 0:
            raise OSError(f"BCryptDeriveKeyPBKDF2 failed: {rc:#x}")
        return out.raw
    finally:
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


# ---------------------------------------------------------------------------
# Overlay format
# ---------------------------------------------------------------------------

PZ_MAGIC = b"PZPK"
PZ_VERSION = 1
FLAG_COMPRESSED = 0x0001
FLAG_DLL = 0x0002
FLAG_PASSWORD = 0x0004
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
SALT_LEN = 16
DEFAULT_ITERATIONS = 200_000

HEADER_FMT = "<4sHHIII"          # magic, ver, flags, orig, comp, enc
HEADER_FIXED = struct.calcsize(HEADER_FMT) + 4 + 12 + 16 + 32 + 32
# crc32(4) + nonce(12) + tag(16) + keyXor(32) + keyPad(32)
assert HEADER_FIXED == 4 + 2 + 2 + 4 + 4 + 4 + 4 + 12 + 16 + 32 + 32  # 116


# NOTE: Both sides authenticate the FULL 116-byte header with the tag
# field (offset 36..52) ZEROED as AAD, since authenticating the final
# tag would be circular. The stub makes the identical zeroed-tag copy
# of the header before calling BCryptDecrypt.
def _build_overlay(image: bytes, password: str | None = None,
                   compress: bool = True, is_dll: bool = False) -> tuple[bytes, dict]:
    flags = FLAG_DLL if is_dll else 0
    payload = image
    if compress:
        c = lz4_compress(image)
        if len(c) < len(image):
            payload = c
            flags |= FLAG_COMPRESSED

    key_pad = os.urandom(KEY_LEN)
    pw_section = b""
    if password:
        salt = os.urandom(SALT_LEN)
        key = pbkdf2_sha256(password.encode("utf-8"), salt, DEFAULT_ITERATIONS)
        flags |= FLAG_PASSWORD
        pw_bytes = password.encode("utf-8")
        pw_xor = bytes(pw_bytes[i] ^ key_pad[i % KEY_LEN] for i in range(len(pw_bytes)))
        pw_section = salt + struct.pack("<IH", DEFAULT_ITERATIONS, len(pw_bytes)) + pw_xor
    else:
        key = os.urandom(KEY_LEN)

    key_xor = bytes(key[i] ^ key_pad[i] for i in range(KEY_LEN))
    nonce = os.urandom(NONCE_LEN)

    pre = struct.pack(HEADER_FMT, PZ_MAGIC, PZ_VERSION, flags,
                      len(image), len(payload), len(payload))
    pre += struct.pack("<I", zlib.crc32(image) & 0xFFFFFFFF) + nonce
    # header = pre(36) + tag(16) + keyXor(32) + keyPad(32)
    aad = pre + b"\x00" * TAG_LEN + key_xor + key_pad
    ct, tag = aes256gcm_encrypt(key, nonce, aad, payload)
    header = pre + tag + key_xor + key_pad
    assert len(header) == HEADER_FIXED

    overlay = header + pw_section + ct
    stats = {
        "orig": len(image),
        "packed": len(overlay),
        "compressed": bool(flags & FLAG_COMPRESSED),
        "encrypted": True,
        "password": bool(password),
        "ratio": len(overlay) / max(1, len(image)),
    }
    return overlay, stats


# ---------------------------------------------------------------------------
# Stub PE patching (append overlay into the last section's raw data)
# ---------------------------------------------------------------------------

def append_overlay_to_stub(stub: bytes, overlay: bytes) -> bytes:
    pe = PE(stub)
    last = max(pe.sections, key=lambda s: s["rawptr"] + s["rawsize"])
    sec_end = align_up(last["rawptr"] + last["rawsize"], pe.file_align)
    if len(stub) > sec_end:
        raise PEError("stub binary has data after the last section; use a freshly built stub")

    out = bytearray(stub)
    out += b"\x00" * (sec_end - len(out))          # pad to aligned section end
    ov_off = len(out)
    out += overlay
    new_raw = (ov_off - last["rawptr"]) + len(overlay)
    new_raw_aligned = align_up(new_raw, pe.file_align)
    out += b"\x00" * (new_raw_aligned - new_raw)    # pad to file alignment

    new_vsize = new_raw_aligned
    struct.pack_into("<I", out, last["hdr_off"] + 8, new_vsize)      # VirtualSize
    struct.pack_into("<I", out, last["hdr_off"] + 16, new_raw_aligned)  # SizeOfRawData
    last["chars"] |= 0x40000000  # IMAGE_SCN_MEM_READ
    struct.pack_into("<I", out, last["hdr_off"] + 36, last["chars"])
    new_size_of_image = align_up(last["vaddr"] + new_vsize, pe.sect_align)
    struct.pack_into("<I", out, pe.opt + 56, new_size_of_image)
    return bytes(out)


# ---------------------------------------------------------------------------
# Verify (decrypt a packed stub without executing anything)
# ---------------------------------------------------------------------------

def verify_packed(path: str) -> dict:
    data = open(path, "rb").read()
    pe = PE(data)
    # locate overlay: scan for magic after headers
    off = data.find(PZ_MAGIC, pe.size_of_headers)
    if off < 0:
        raise PEError("no PZPK overlay found")
    magic, ver, flags, orig, comp, enc = struct.unpack_from(HEADER_FMT, data, off)
    crc = struct.unpack_from("<I", data, off + 20)[0]
    nonce = data[off + 24:off + 36]
    tag = data[off + 36:off + 52]
    key_xor = data[off + 52:off + 84]
    key_pad = data[off + 84:off + 116]
    p = off + HEADER_FIXED
    pw_section = b""
    if flags & FLAG_PASSWORD:
        salt = data[p:p + 16]
        iters, pw_len = struct.unpack_from("<IH", data, p + 16)
        pw_xor = data[p + 22:p + 22 + pw_len]
        pw_section = data[p:p + 22 + pw_len]
        pw = bytes(pw_xor[i] ^ key_pad[i % KEY_LEN] for i in range(pw_len))
        key = pbkdf2_sha256(pw, salt, iters)
        p += 22 + pw_len
    else:
        key = bytes(key_xor[i] ^ key_pad[i] for i in range(KEY_LEN))
    ct = data[p:p + enc]
    aad = data[off:off + 36] + b"\x00" * TAG_LEN + key_xor + key_pad
    payload = aes256gcm_decrypt(key, nonce, aad, ct, tag)
    if zlib.crc32((lz4_decompress(payload, orig) if flags & FLAG_COMPRESSED else payload)) & 0xFFFFFFFF != crc:
        raise PEError("CRC mismatch")
    image = lz4_decompress(payload, orig) if flags & FLAG_COMPRESSED else payload
    inner = PE(image)
    return {
        "flags": flags,
        "original_size": orig,
        "payload_size": enc,
        "compressed": bool(flags & FLAG_COMPRESSED),
        "dll": bool(flags & FLAG_DLL),
        "crc_ok": True,
        "auth_ok": True,
        "inner_entry_rva": hex(inner.entry),
        "inner_sections": len(inner.sections),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def find_stub(is_dll: bool) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "stub"), here, "."):
        name = "stub_dll.dll" if is_dll else "stub_exe.exe"
        p = os.path.join(c, name)
        if os.path.exists(p):
            return p
    raise PEError(
        "stub binary not found. Build it first: run build.bat (MSVC or MinGW-w64), "
        "or pass --stub <path>."
    )


def cmd_pack(a):
    image = open(a.input, "rb").read()
    try:
        pe = PE(image)
        warns = pe.check_support()
    except PEError as e:
        print(f"[!] refused: {e}", file=sys.stderr)
        return 2
    for w in warns:
        print(f"[i] warning: {w}", file=sys.stderr)

    is_dll = pe.is_dll
    if a.stub:
        stub_path = a.stub
    else:
        stub_path = find_stub(is_dll)
    stub = open(stub_path, "rb").read()

    overlay, stats = _build_overlay(image, a.password,
                                     compress=not a.no_compress, is_dll=is_dll)

    out = append_overlay_to_stub(stub, overlay)
    open(a.output, "wb").write(out)
    print(f"[+] packed {a.input} -> {a.output}")
    print(f"    original : {stats['orig']:,} bytes")
    print(f"    packed   : {stats['packed']:,} bytes  (overlay; total file {len(out):,})")
    print(f"    method   : AES-256-GCM + {'LZ4' if stats['compressed'] else 'stored'}  (backend: {_crypto_backend})")
    print(f"    password : {'yes (PBKDF2-SHA256, 200k iters, embedded)' if stats['password'] else 'no (random key, embedded)'}")
    print(f"    payload  : {'DLL' if is_dll else 'EXE'}")
    print("[i] note: run --verify on the output to confirm integrity without executing it")
    return 0


def cmd_verify(a):
    try:
        info = verify_packed(a.input)
    except Exception as e:
        print(f"[!] verification FAILED: {e}", file=sys.stderr)
        return 1
    print(f"[+] verification OK: {a.input}")
    for k, v in info.items():
        print(f"    {k:16s}: {v}")
    return 0


def cmd_selftest(a):
    print(f"[*] crypto backend: {_crypto_backend}")
    # 1) LZ4 round-trip
    for data in (b"", b"A" * 100000, bytes(range(256)) * 512,
                 os.urandom(65536) + b"repeatme" * 4096):
        c = lz4_compress(data)
        assert lz4_decompress(c, len(data)) == data, "LZ4 round-trip failed"
    print("[+] LZ4 codec round-trip: OK")
    # 2) AES-GCM known-answer vectors (NIST SP 800-38D, AES-128-GCM,
    #    all-zero key/IV). Validates the backend against published
    #    test vectors.
    zkey = bytes(16)
    znonce = bytes(12)
    # Test case 1: empty plaintext, no AAD -> tag 58e2fcce...
    ct, tag = aes256gcm_encrypt(zkey, znonce, b"", b"")
    assert ct == b"" and tag == bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
    # Test case 3: 16 zero bytes, no AAD
    ct, tag = aes256gcm_encrypt(zkey, znonce, b"", bytes(16))
    assert ct == bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    assert tag == bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")
    print("[+] AES-GCM NIST SP 800-38D known-answer vectors: OK")
    # 3) AES-GCM round-trip + wrong-key rejection
    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"packerzero-aad"
    ct, tag = aes256gcm_encrypt(key, nonce, aad, b"secret payload")
    assert aes256gcm_decrypt(key, nonce, aad, ct, tag) == b"secret payload"
    try:
        aes256gcm_decrypt(os.urandom(32), nonce, aad, ct, tag)
        raise AssertionError("wrong key unexpectedly accepted")
    except OSError:
        pass
    print("[+] AES-256-GCM round-trip + wrong-key rejection: OK")
    # 4) PBKDF2 determinism
    k1 = pbkdf2_sha256(b"pw", b"salt", 1000)
    k2 = pbkdf2_sha256(b"pw", b"salt", 1000)
    assert k1 == k2 and len(k1) == 32
    print("[+] PBKDF2-SHA256 determinism: OK")
    # 4) overlay build + stub patching on a synthetic PE
    synth = _synthetic_pe()
    overlay, stats = _build_overlay(synth, "hunter2", compress=True)
    patched = append_overlay_to_stub(synth, overlay)
    # sanity: patched still parses, overlay still verifies
    pe2 = PE(patched)
    assert pe2.size_of_image >= PE(synth).size_of_image
    open(a.tmp, "wb").write(patched)
    info = verify_packed(a.tmp)
    assert info["auth_ok"] and info["crc_ok"] and info["original_size"] == len(synth)
    os.remove(a.tmp)
    print("[+] overlay build + stub patching + verify: OK")
    print("[+] selftest passed")
    return 0


def _synthetic_pe() -> bytes:
    """Minimal PE32+ EXE for exercising the packer's header-editing code."""
    sect_align, file_align = 0x1000, 0x200
    code = b"\x48\x31\xC0\xC3"  # xor rax,rax; ret
    raw = align_up(len(code), file_align)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)          # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)        # entry point RVA
    struct.pack_into("<Q", opt, 24, 0x140000000)   # image base
    struct.pack_into("<I", opt, 32, sect_align)
    struct.pack_into("<I", opt, 36, file_align)
    struct.pack_into("<I", opt, 56, align_up(0x1000 + raw, sect_align))  # size of image
    struct.pack_into("<I", opt, 60, 0x200)         # size of headers
    struct.pack_into("<I", opt, 108, 16)           # num RVA sizes
    # headers
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x8664)        # AMD64
    struct.pack_into("<H", coff, 2, 1)             # 1 section
    struct.pack_into("<H", coff, 16, 240)          # opt header size
    struct.pack_into("<H", coff, 18, 0x0022)       # executable image
    nt = b"PE\x00\x00" + bytes(coff) + bytes(opt)
    sec = bytearray(40)
    sec[:6] = b".text\x00"
    struct.pack_into("<I", sec, 8, raw)            # virtual size
    struct.pack_into("<I", sec, 12, 0x1000)        # virtual addr
    struct.pack_into("<I", sec, 16, raw)           # raw size
    struct.pack_into("<I", sec, 20, 0x200)         # raw ptr
    struct.pack_into("<I", sec, 36, 0x60000020)    # code|exec|read
    headers = bytes(dos) + b"\x00" * (0x80 - 0x40) + nt + bytes(sec)
    headers += b"\x00" * (0x200 - len(headers))
    body = code + b"\x00" * (raw - len(code))
    return headers + body


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="packerzero",
        description="PackerZero v1.0 - legitimate PE packer/protector (x64)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pack", help="pack an EXE or DLL")
    p.add_argument("input", help="input PE32+ file")
    p.add_argument("output", help="output packed file")
    p.add_argument("--password", default=None,
                   help="password (PBKDF2-derived key). NOTE: embedded in the "
                        "output, so this is obfuscation-grade only.")
    p.add_argument("--no-compress", action="store_true", help="skip LZ4 compression")
    p.add_argument("--stub", default=None, help="path to stub_exe.exe / stub_dll.dll")
    p.set_defaults(func=cmd_pack)

    v = sub.add_parser("verify", help="verify a packed file (decrypt + CRC, no execution)")
    v.add_argument("input", help="packed file")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("selftest", help="run codec/crypto/packaging self-tests")
    t.add_argument("--tmp", default="packerzero_selftest.tmp")
    t.set_defaults(func=cmd_selftest)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
