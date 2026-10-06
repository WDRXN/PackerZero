/*
 * PackerZero v1.0 - runtime stub (x64 Windows)
 * -------------------------------------------
 * Legitimate PE protector stub. Loads an AES-256-GCM encrypted,
 * optionally LZ4-compressed PE image from the section overlay of THIS binary,
 * maps it in memory (relocations + imports), verifies CRC32 integrity,
 * and transfers control to the original entry point.
 *
 * No CRT. Win32 + CNG (bcrypt.dll) only.
 *
 * MSVC:
 *   cl /nologo /O2 /GS- /Gy /NODEFAULTLIB /entry:StubEntry /link ^
 *      /SUBSYSTEM:WINDOWS /NODEFAULTLIB kernel32.lib bcrypt.lib ^
 *      /OUT:stub_exe.exe stub.c
 * MSVC (DLL stub): add /DSTUB_DLL /entry:DllMainStub /DLL
 *
 * MinGW-w64:
 *   x86_64-w64-mingw32-gcc -O2 -nostdlib -fno-stack-protector -o stub_exe.exe ^
 *      stub.c -Wl,--entry=StubEntry -lkernel32 -lbcrypt -lgcc
 *   DLL: add -DSTUB_DLL -shared -Wl,--entry=DllMainStub
 *
 * [Xyberix] - Protector Module - Requires Manual Build - No Auto-Execution
 */

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma strict_gs_check(off)

#define PZ_MAGIC0 'P'
#define PZ_MAGIC1 'Z'
#define PZ_MAGIC2 'P'
#define PZ_MAGIC3 'K'
#define PZ_VERSION 1

#define PZ_FLAG_COMPRESSED 0x0001
#define PZ_FLAG_DLL        0x0002
#define PZ_FLAG_PASSWORD   0x0004

#define PZ_NONCE_LEN  12
#define PZ_TAG_LEN    16
#define PZ_KEY_LEN    32
#define PZ_SALT_LEN   16

#pragma pack(push, 1)
typedef struct _PZ_HEADER {
    unsigned char  magic[4];     /* 'PZPK'                       */
    unsigned short ver;          /* PZ_VERSION                   */
    unsigned short flags;        /* PZ_FLAG_*                    */
    unsigned int   origSize;     /* decompressed image size      */
    unsigned int   compSize;     /* compressed size (==encSize)  */
    unsigned int   encSize;      /* encrypted payload size       */
    unsigned int   crc32;        /* CRC32 of the original image  */
    unsigned char  nonce[PZ_NONCE_LEN];
    unsigned char  tag[PZ_TAG_LEN];
    unsigned char  keyXor[PZ_KEY_LEN];   /* key = keyXor ^ keyPad  */
    unsigned char  keyPad[PZ_KEY_LEN];
    /* if PZ_FLAG_PASSWORD:  salt[16] + iterations(u32) + pwLen(u16) + pwXor[pwLen] */
} PZ_HEADER;
#pragma pack(pop)

/* ---------------- no-CRT helpers ---------------- */
static void *PZ_memcpy(void *d, const void *s, size_t n)
{
    unsigned char *dd = (unsigned char *)d;
    const unsigned char *ss = (const unsigned char *)s;
    while (n--) *dd++ = *ss++;
    return d;
}
static void PZ_memset(void *d, int c, size_t n)
{
    unsigned char *dd = (unsigned char *)d;
    while (n--) *dd++ = (unsigned char)c;
}
static size_t PZ_strlenA(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
static void *PZ_alloc(size_t n)      { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
static void  PZ_free(void *p)        { if (p) HeapFree(GetProcessHeap(), 0, p); }

/* ---------------- CRC32 (zlib compatible) ---------------- */
static const unsigned int PZ_crc_table[256] = {
    0x00000000u,0x77073096u,0xEE0E612Cu,0x990951BAu,0x076DC419u,0x706AF48Fu,0xE963A535u,0x9E6495A3u,
    0x0EDB8832u,0x79DCB8A4u,0xE0D5E91Eu,0x97D2D988u,0x09B64C2Bu,0x7EB17CBDu,0xE7B82D07u,0x90BF1D91u,
    0x1DB71064u,0x6AB020F2u,0xF3B97148u,0x84BE41DEu,0x1ADAD47Du,0x6DDDE4EBu,0xF4D4B551u,0x83D385C7u,
    0x136C9856u,0x646BA8C0u,0xFD62F97Au,0x8A65C9ECu,0x14015C4Fu,0x63066CD9u,0xFA0F3D63u,0x8D080DF5u,
    0x3B6E20C8u,0x4C69105Eu,0xD56041E4u,0xA2677172u,0x3C03E4D1u,0x4B04D447u,0xD20D85FDu,0xA50AB56Bu,
    0x35B5A8FAu,0x42B2986Cu,0xDBBBC9D6u,0xACBCF940u,0x32D86CE3u,0x45DF5C75u,0xDCD60DCFu,0xABD13D59u,
    0x26D930ACu,0x51DE003Au,0xC8D75180u,0xBFD06116u,0x21B4F4B5u,0x56B3C423u,0xCFBA9599u,0xB8BDA50Fu,
    0x2802B89Eu,0x5F058808u,0xC60CD9B2u,0xB10BE924u,0x2F6F7C87u,0x58684C11u,0xC1611DABu,0xB6662D3Du,
    0x76DC4190u,0x01DB7106u,0x98D220BCu,0xEFD5102Au,0x71B18589u,0x06B6B51Fu,0x9FBFE4A5u,0xE8B8D433u,
    0x7807C9A2u,0x0F00F934u,0x9609A88Eu,0xE10E9818u,0x7F6A0DBBu,0x086D3D2Du,0x91646C97u,0xE6635C01u,
    0x6B6B51F4u,0x1C6C6162u,0x856530D8u,0xF262004Eu,0x6C0695EDu,0x1B01A57Bu,0x8208F4C1u,0xF50FC457u,
    0x65B0D9C6u,0x12B7E950u,0x8BBEB8EAu,0xFCB9887Cu,0x62DD1DDFu,0x15DA2D49u,0x8CD37CF3u,0xFBD44C65u,
    0x4DB26158u,0x3AB551CEu,0xA3BC0074u,0xD4BB30E2u,0x4ADFA541u,0x3DD895D7u,0xA4D1C46Du,0xD3D6F4FBu,
    0x4369E96Au,0x346ED9FCu,0xAD678846u,0xDA60B8D0u,0x44042D73u,0x33031DE5u,0xAA0A4C5Fu,0xDD0D7CC9u,
    0x5005713Cu,0x270241AAu,0xBE0B1010u,0xC90C2086u,0x5768B525u,0x206F85B3u,0xB966D409u,0xCE61E49Fu,
    0x5EDEF90Eu,0x29D9C998u,0xB0D09822u,0xC7D7A8B4u,0x59B33D17u,0x2EB40D81u,0xB7BD5C3Bu,0xC0BA6CADu,
    0xEDB88320u,0x9ABFB3B6u,0x03B6E20Cu,0x74B1D29Au,0xEAD54739u,0x9DD277AFu,0x04DB2615u,0x73DC1683u,
    0xE3630B12u,0x94643B84u,0x0D6D6A3Eu,0x7A6A5AA8u,0xE40ECF0Bu,0x9309FF9Du,0x0A00AE27u,0x7D079EB1u,
    0xF00F9344u,0x8708A3D2u,0x1E01F268u,0x6906C2FEu,0xF7625758u,0x806567CBu,0x196C3671u,0x6E6B06E7u,
    0xFED41B76u,0x89D32BE0u,0x10DA7A5Au,0x67DD4ACCu,0xF9B9DF6Fu,0x8EBEEFF9u,0x17B7BE43u,0x60B08ED5u,
    0xD6D6A3E8u,0xA1D1937Eu,0x40DF0B66u,0x37D83BF0u,0xA9BCAE53u,0xDEBB9EC5u,0x47B2CF7Fu,0x30B5FFE9u,
    0xBDBDF21Cu,0xCABAC28Au,0x53B39330u,0x24B4A3A6u,0xBAD03605u,0xCDD70693u,0x54DE5729u,0x23D967BFu,
    0xB3667A2Eu,0xC4614AB8u,0x5D681B02u,0x2A6F2B94u,0xB40BBE37u,0xC30C8EA1u,0x5A05DF1Bu,0x2D02EF8Du
};
static unsigned int PZ_crc32(const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    unsigned int crc = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < len; i++)
        crc = PZ_crc_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ---------------- LZ4 block decompressor ----------------
 * Standard LZ4 block format: token | [lit-ext] literals offset [match-ext] ...
 * The compressor used is the one shipped with packer.py.
 * ------------------------------------------------------ */
static int PZ_lz4_decompress(const unsigned char *src, size_t srcSize,
                             unsigned char *dst, size_t dstCapacity)
{
    const unsigned char *s = src;
    const unsigned char *sEnd = src + srcSize;
    unsigned char *d = dst;
    unsigned char *dEnd = dst + dstCapacity;

    while (s < sEnd) {
        unsigned char token = *s++;
        size_t litLen = (size_t)(token >> 4);
        size_t matchLen = (size_t)(token & 15);
        size_t off, i;

        if (litLen == 15) {
            size_t e;
            do {
                if (s >= sEnd) return 0;
                e = *s++;
                litLen += e;
            } while (e == 255);
        }
        if ((size_t)(sEnd - s) < litLen) return 0;
        if ((size_t)(dEnd - d) < litLen) return 0;
        PZ_memcpy(d, s, litLen);
        d += litLen;
        s += litLen;

        if (s >= sEnd) break;               /* last run: literals only */
        if ((size_t)(sEnd - s) < 2) return 0;
        off = (size_t)s[0] | ((size_t)s[1] << 8);
        s += 2;
        if (off == 0 || off > (size_t)(d - dst)) return 0;

        if (matchLen == 15) {
            size_t e;
            do {
                if (s >= sEnd) return 0;
                e = *s++;
                matchLen += e;
            } while (e == 255);
        }
        matchLen += 4;                      /* LZ4 MINMATCH */
        if ((size_t)(dEnd - d) < matchLen) return 0;
        {
            const unsigned char *match = d - off;
            for (i = 0; i < matchLen; i++)  /* byte-wise: handles overlap */
                d[i] = match[i];
        }
        d += matchLen;
    }
    return 1;
}

/* ---------------- overlay discovery ---------------- */
static const PZ_HEADER *PZ_find_overlay(void)
{
    const unsigned char *base = (const unsigned char *)GetModuleHandleW(NULL);
    const IMAGE_NT_HEADERS64 *nt;
    const unsigned char *scan, *scanEnd;
    DWORD e_lfanew;
    DWORD sizeOfImage, sizeOfHeaders;

    if (!base || base[0] != 'M' || base[1] != 'Z') return NULL;
    PZ_memcpy((void *)&e_lfanew, base + 0x3C, 4);
    if (!e_lfanew) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)(base + e_lfanew);
    if (nt->Signature != 0x00004550) return NULL;
    if (nt->OptionalHeader.Magic != 0x20B) return NULL;      /* PE32+ only */

    sizeOfImage    = nt->OptionalHeader.SizeOfImage;
    sizeOfHeaders  = nt->OptionalHeader.SizeOfHeaders;
    scan    = base + sizeOfHeaders;
    scanEnd = base + sizeOfImage;

    for (; scan + sizeof(PZ_HEADER) <= scanEnd; scan++) {
        const PZ_HEADER *h = (const PZ_HEADER *)scan;
        size_t pwExtra = 0;
        if (h->magic[0] != PZ_MAGIC0 || h->magic[1] != PZ_MAGIC1 ||
            h->magic[2] != PZ_MAGIC2 || h->magic[3] != PZ_MAGIC3) continue;
        if (h->ver != PZ_VERSION) continue;
        if (h->origSize == 0 || h->encSize == 0 || h->encSize != h->compSize) continue;
        if (h->flags & PZ_FLAG_PASSWORD) {
            if ((size_t)(scanEnd - scan) < sizeof(PZ_HEADER) + 22) continue;
            pwExtra = 16 + 4 + 2 + (size_t)*(const unsigned short *)(scan + sizeof(PZ_HEADER) + 16 + 4);
        }
        if ((size_t)(scanEnd - scan) < sizeof(PZ_HEADER) + pwExtra + h->encSize) continue;
        return h;
    }
    return NULL;
}

/* ---------------- image mapping ---------------- */
static DWORD PZ_map_protection(DWORD chars)
{
    if (chars & IMAGE_SCN_MEM_EXECUTE)
        return (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
}

static void PZ_apply_relocs(unsigned char *base, const IMAGE_NT_HEADERS64 *nt, ULONGLONG delta)
{
    DWORD relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    IMAGE_BASE_RELOCATION *r;
    if (!relDir || !delta) return;
    r = (IMAGE_BASE_RELOCATION *)(base + relDir);
    while (r->VirtualAddress && r->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        DWORD count = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        const unsigned short *e = (const unsigned short *)(r + 1);
        DWORD i;
        for (i = 0; i < count; i++) {
            DWORD type = e[i] >> 12;
            DWORD off  = e[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG *p = (ULONGLONG *)(base + r->VirtualAddress + off);
                *p += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD *p = (DWORD *)(base + r->VirtualAddress + off);
                *p += (DWORD)delta;
            }
        }
        r = (IMAGE_BASE_RELOCATION *)((unsigned char *)r + r->SizeOfBlock);
    }
}

static int PZ_resolve_imports(unsigned char *base, const IMAGE_NT_HEADERS64 *nt)
{
    DWORD impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR *desc;
    if (!impDir) return 1;
    desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + impDir);
    for (; desc->Name; desc++) {
        const char *dllName = (const char *)(base + desc->Name);
        HMODULE h = LoadLibraryA(dllName);
        IMAGE_THUNK_DATA64 *oft, *ft;
        if (!h) return 0;
        oft = (IMAGE_THUNK_DATA64 *)(base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                                       : desc->FirstThunk));
        ft  = (IMAGE_THUNK_DATA64 *)(base + desc->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            FARPROC proc;
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                proc = GetProcAddress(h, MAKEINTRESOURCEA((DWORD)(oft->u1.Ordinal & 0xFFFF)));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
                proc = GetProcAddress(h, (LPCSTR)ibn->Name);
            }
            if (!proc) return 0;
            ft->u1.Function = (ULONGLONG)(UINT_PTR)proc;
        }
    }
    return 1;
}

/* Maps a raw PE32+ image (file bytes) into memory and returns the base. */
static unsigned char *PZ_map_image(const unsigned char *img, size_t imgSize)
{
    const IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    DWORD e_lfanew, sizeOfImage, sizeOfHeaders;
    ULONGLONG prefBase, delta;
    unsigned char *base;
    DWORD i;

    if (imgSize < 0x40 || img[0] != 'M' || img[1] != 'Z') return NULL;
    PZ_memcpy((void *)&e_lfanew, img + 0x3C, 4);
    if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) > imgSize) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)(img + e_lfanew);
    if (nt->Signature != 0x00004550 || nt->OptionalHeader.Magic != 0x20B) return NULL;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;

    sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    prefBase      = nt->OptionalHeader.ImageBase;

    base = (unsigned char *)VirtualAlloc((LPVOID)(DWORD_PTR)prefBase, sizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        base = (unsigned char *)VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return NULL;

    delta = (ULONGLONG)(UINT_PTR)base - prefBase;

    if (sizeOfHeaders > imgSize) sizeOfHeaders = (DWORD)imgSize;
    PZ_memcpy(base, img, sizeOfHeaders);

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD vsize = sec[i].VirtualSize ? sec[i].VirtualSize : sec[i].SizeOfRawData;
        DWORD rs = sec[i].SizeOfRawData;
        if (!vsize) continue;
        if (sec[i].VirtualAddress + vsize > sizeOfImage)
            vsize = sizeOfImage - sec[i].VirtualAddress;
        PZ_memset(base + sec[i].VirtualAddress, 0, vsize);
        if (sec[i].PointerToRawData && rs) {
            if (sec[i].PointerToRawData + rs > imgSize)
                rs = (DWORD)(imgSize - sec[i].PointerToRawData);
            PZ_memcpy(base + sec[i].VirtualAddress, img + sec[i].PointerToRawData, rs);
        }
    }

    if (delta) PZ_apply_relocs(base, nt, delta);
    if (!PZ_resolve_imports(base, nt)) { VirtualFree(base, 0, MEM_RELEASE); return NULL; }

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD vsize = sec[i].VirtualSize ? sec[i].VirtualSize : sec[i].SizeOfRawData;
        DWORD old = 0;
        if (!vsize) continue;
        if (sec[i].VirtualAddress + vsize > sizeOfImage)
            vsize = sizeOfImage - sec[i].VirtualAddress;
        VirtualProtect(base + sec[i].VirtualAddress, vsize, PZ_map_protection(sec[i].Characteristics), &old);
    }
    return base;
}

/* ---------------- crypto ---------------- */
static int PZ_aes256gcm_decrypt(BCRYPT_KEY_HANDLE kh,
                                const unsigned char *nonce,
                                const unsigned char *aad, ULONG aadLen,
                                const unsigned char *ct, ULONG ctLen,
                                const unsigned char *tag,
                                unsigned char *out)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG outLen = 0;
    NTSTATUS st;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce   = (PUCHAR)(UINT_PTR)nonce;
    info.cbNonce   = PZ_NONCE_LEN;
    info.pbAuthData = (PUCHAR)(UINT_PTR)aad;
    info.cbAuthData = aadLen;
    info.pbTag     = (PUCHAR)(UINT_PTR)tag;
    info.cbTag     = PZ_TAG_LEN;
    st = BCryptDecrypt(kh, (PUCHAR)(UINT_PTR)ct, ctLen, &info, NULL, 0,
                       out, ctLen, &outLen, 0);
    return (st >= 0 && outLen == ctLen);
}

static int PZ_derive_key(const unsigned char *password, DWORD pwLen,
                         const unsigned char *salt, DWORD iterations,
                         unsigned char *keyOut)
{
    BCRYPT_ALG_HANDLE hPbkdf = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hPbkdf, BCRYPT_PBKDF2_ALGORITHM, NULL, 0);
    if (st < 0) return 0;
    st = BCryptDeriveKeyPBKDF2(hPbkdf, (PUCHAR)(UINT_PTR)password, pwLen,
                               (PUCHAR)(UINT_PTR)salt, PZ_SALT_LEN,
                               iterations, keyOut, PZ_KEY_LEN, 0);
    BCryptCloseAlgorithmProvider(hPbkdf, 0);
    return st >= 0;
}

/* ---------------- payload runner ---------------- */
static unsigned char *g_mapped = NULL;

static int PZ_run_payload(void)
{
    const PZ_HEADER *h = PZ_find_overlay();
    const unsigned char *payloadPtr;
    size_t pwExtra = 0;
    unsigned char key[PZ_KEY_LEN];
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PUCHAR keyObj = NULL, plain = NULL, image = NULL, pwBuf = NULL;
    ULONG keyObjLen = 0, resLen = 0;
    DWORD pwBufLen = 0;
    int ok = 0;
    DWORD i;

    if (!h) return 0;

    /* rebuild embedded key */
    for (i = 0; i < PZ_KEY_LEN; i++)
        key[i] = h->keyXor[i] ^ h->keyPad[i];

    payloadPtr = (const unsigned char *)h + sizeof(PZ_HEADER);

    if (h->flags & PZ_FLAG_PASSWORD) {
        const unsigned char *p = payloadPtr;
        unsigned char salt[PZ_SALT_LEN];
        DWORD iters, j;
        WORD pwLen;
        for (i = 0; i < PZ_SALT_LEN; i++) salt[i] = p[i];
        PZ_memcpy((void *)&iters, p + PZ_SALT_LEN, 4);
        PZ_memcpy((void *)&pwLen, p + PZ_SALT_LEN + 4, 2);
        pwExtra = PZ_SALT_LEN + 4 + 2 + (size_t)pwLen;
        pwBuf = (unsigned char *)PZ_alloc(pwLen ? pwLen : 1);
        if (!pwBuf) goto done;
        pwBufLen = pwLen;
        for (j = 0; j < pwLen; j++)
            pwBuf[j] = p[PZ_SALT_LEN + 4 + 2 + j] ^ h->keyPad[j % PZ_KEY_LEN];
        PZ_memset(key, 0, sizeof(key));
        if (!PZ_derive_key(pwBuf, pwLen, salt, iters, key)) goto done;
        payloadPtr += pwExtra;
    }

    /* AES-256-GCM decrypt. */
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto done;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto done;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&keyObjLen, sizeof(keyObjLen), &resLen, 0) < 0) goto done;
    keyObj = (PUCHAR)PZ_alloc(keyObjLen ? keyObjLen : 1);
    if (!keyObj) goto done;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjLen,
                                   key, PZ_KEY_LEN, 0) < 0) goto done;

    plain = (PUCHAR)PZ_alloc(h->encSize ? h->encSize : 1);
    if (!plain) goto done;

    /*
     * AAD = the full 116-byte header with the tag field (offset 36..52)
     * zeroed. The packer authenticates the same zeroed-tag header view,
     * since authenticating the final tag would be circular.
     */
    {
        unsigned char aad[sizeof(PZ_HEADER)];
        PZ_memcpy(aad, h, sizeof(PZ_HEADER));
        PZ_memset(aad + 36, 0, PZ_TAG_LEN);
        ok = PZ_aes256gcm_decrypt(hKey, h->nonce, aad, sizeof(PZ_HEADER),
                                        payloadPtr, h->encSize, h->tag, plain);
    }
    if (!ok) goto done;

    /* decompress + integrity check */
    if (h->flags & PZ_FLAG_COMPRESSED) {
        image = (unsigned char *)PZ_alloc(h->origSize ? h->origSize : 1);
        if (!image) goto done;
        if (!PZ_lz4_decompress(plain, h->encSize, image, h->origSize)) goto done;
    } else {
        image = plain;
        plain = NULL;
    }
    if (PZ_crc32(image, h->origSize) != h->crc32) goto done;

    /* map and transfer control */
    g_mapped = PZ_map_image(image, h->origSize);
    if (!g_mapped) goto done;
    ok = 1;

done:
    if (keyObj) PZ_memset(keyObj, 0, keyObjLen);
    if (plain)  { PZ_memset(plain, 0, h->encSize); PZ_free(plain); }
    if (image && image != plain) { PZ_memset(image, 0, h->origSize); PZ_free(image); }
    if (pwBuf)  { PZ_memset(pwBuf, 0, pwBufLen); PZ_free(pwBuf); }
    PZ_memset(key, 0, sizeof(key));
    if (hKey && hAlg) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ---------------- entry points ---------------- */
#ifdef STUB_DLL

typedef BOOL (WINAPI *DllMainFn)(HINSTANCE, DWORD, LPVOID);

BOOL WINAPI DllMainStub(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        if (!PZ_run_payload()) return FALSE;
        if (g_mapped) {
            const IMAGE_NT_HEADERS64 *nt;
            DWORD e_lfanew = 0;
            PZ_memcpy((void *)&e_lfanew, g_mapped + 0x3C, 4);
            nt = (const IMAGE_NT_HEADERS64 *)(g_mapped + e_lfanew);
            if (nt->OptionalHeader.AddressOfEntryPoint) {
                DllMainFn fn = (DllMainFn)(g_mapped + nt->OptionalHeader.AddressOfEntryPoint);
                return fn(g_mapped, DLL_PROCESS_ATTACH, lpvReserved);
            }
        }
    } else if (g_mapped) {
        const IMAGE_NT_HEADERS64 *nt;
        DWORD e_lfanew = 0;
        PZ_memcpy((void *)&e_lfanew, g_mapped + 0x3C, 4);
        nt = (const IMAGE_NT_HEADERS64 *)(g_mapped + e_lfanew);
        if (nt->OptionalHeader.AddressOfEntryPoint) {
            DllMainFn fn = (DllMainFn)(g_mapped + nt->OptionalHeader.AddressOfEntryPoint);
            if (fdwReason == DLL_PROCESS_DETACH) {
                BOOL r = fn(g_mapped, DLL_PROCESS_DETACH, lpvReserved);
                VirtualFree(g_mapped, 0, MEM_RELEASE);
                g_mapped = NULL;
                return r;
            }
            return fn(g_mapped, fdwReason, lpvReserved);
        }
    }
    return TRUE;
}

#else /* EXE stub */

typedef int (WINAPI *EntryFn)(HINSTANCE, DWORD, LPVOID);

int WINAPI StubEntry(HINSTANCE hinst, DWORD dwReason, LPVOID lpReserved)
{
    (void)hinst; (void)dwReason; (void)lpReserved;
    if (!PZ_run_payload())
        return 1;
    {
        const IMAGE_NT_HEADERS64 *nt;
        DWORD e_lfanew = 0;
        PZ_memcpy((void *)&e_lfanew, g_mapped + 0x3C, 4);
        nt = (const IMAGE_NT_HEADERS64 *)(g_mapped + e_lfanew);
        if (nt->OptionalHeader.AddressOfEntryPoint) {
            EntryFn fn = (EntryFn)(g_mapped + nt->OptionalHeader.AddressOfEntryPoint);
            return fn(g_mapped, 0, NULL);
        }
    }
    return 0;
}

#endif
