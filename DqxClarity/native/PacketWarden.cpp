// PacketWarden.dll - injected into DQXGame.exe (x86).
//
// ============================================================================
// HIGH-LEVEL OVERVIEW
// ============================================================================
//
// This dll acts as a transparent man-in-the-middle between DQXGame.exe's
// network packet parser and the c# translation host (DqxClarity). When the
// game receives a network packet, this hook intercepts it, sends it to the
// c# side over a named pipe for translation, and feeds the translated version
// back to the game's parser -- all before the game ever processes the contents.
//
// The game doesn't know its packets were swapped. It sees the same return
// value it would have gotten from the original parser, but the data it
// actually parsed now contains translated strings.
//
// ============================================================================
// PACKET INTERCEPTION FLOW (the core loop)
// ============================================================================
//
// 1. Game calls its VCE packet parser function (ParseNetworkPacket).
//    Because we overwrote the first 5 bytes of that function with a JMP,
//    execution lands in our hook: H_ParseNetworkPacket().
//
// 2. H_ParseNetworkPacket filters the packet:
//    - Skips empty packets (length == 0).
//    - Skips non-data packets (type != 0 and != 4). Types 1/2/3 are
//      ping/pong/ackn control frames -- no translatable content.
//    - Extracts the 3-byte routing key (opcode << 16 | marker1 << 8 | marker2)
//      from the payload and checks it against KNOWN_PACKETS[]. If it's not
//      a packet we care about, pass it through unmodified.
//
// 3. For packets we DO care about, we save the *original* declared packet
//    size from the framing header via ComputeOriginalSize(). This is critical
//    for the return value -- see step 6.
//
// 4. ExchangePacket() sends the raw packet bytes to the c# host over the
//    named pipe (\\.\pipe\dqxclarity):
//      Native -> C#:  [u32 packet_length][raw packet bytes]
//      C# -> Native:  [u8 flag]
//                     If flag == 0: packet was not modified, nothing else sent.
//                     If flag == 1: [u32 new_length][modified packet bytes]
//    The pipe is protected by a critical section since the game's parser can
//    be called from multiple threads.
//
// 5. If the c# side returned a modified packet, we call the *original* parser
//    (via trampoline) with the modified data instead of the original. If no
//    modification was needed, we call through with the original data. Either
//    way, the game's parser processes exactly one packet -- it just might
//    contain translated strings now.
//
// 6. RETURN VALUE: We return the *original* packet's declared size, NOT the
//    modified packet's size. This is the most important detail of the whole
//    hook. The game's caller uses ParseNetworkPacket's return value to advance
//    its read cursor through the network receive buffer. If we returned the
//    modified size (which differs because translated strings are longer or
//    shorter than the originals), the read cursor would land in the middle of
//    the next packet and the entire network stream would desync, crashing the
//    game. By returning original_size, the caller advances past exactly the
//    bytes it received from the server, keeping the stream perfectly aligned.
//
// ============================================================================
// HOOK INSTALLATION
// ============================================================================
//
// On DLL_PROCESS_ATTACH, a background thread (InstallThread) runs the
// following sequence:
//
// 1. FIND THE TARGET: ResolveParser() scans the game's .text section for a
//    body fingerprint unique to the VCE packet parser. This is NOT a fixed
//    address -- it survives game patches as long as the parser's structure
//    doesn't fundamentally change. The fingerprint is:
//      a. scan for `call [reg+0x5C]` and `call [reg+0x64]` (vtable dispatches)
//      b. pair sites within 0x300 bytes (same function body)
//      c. verify each pair has `push 0x16` and `push 0x1B` nearby (log codes
//         22 and 27 -- branch markers inside the parser's switch statement)
//      d. walk backwards through 0xCC padding to find the function prologue
//    Port of C:\Users\joey\Desktop\test\sleep_test.js step-for-step.
//
// 2. INSTALL THE TRAMPOLINE: InstallHook() does a classic inline x86 hook:
//      a. Allocate an executable trampoline buffer (VirtualAlloc RWX).
//      b. Copy the first N bytes of the original function into the trampoline
//         (enough to cover the 5-byte JMP we're about to write). Uses a
//         minimal x86 length disassembler to avoid splitting instructions.
//      c. Append a JMP from the trampoline back to original_fn + N (so
//         calling the trampoline executes the original prologue then continues
//         into the rest of the original function -- this is how we "call the
//         original").
//      d. Overwrite the first 5 bytes of the original function with
//         JMP rel32 -> H_ParseNetworkPacket. NOP-pad any remaining bytes.
//      e. FlushInstructionCache so the CPU picks up the new code.
//
//    After this, any call to the original parser function immediately jumps
//    to our hook. Our hook can call the original via Orig_ParseNet (which
//    points to the trampoline).
//
// 3. PIPE CONNECTION: The pipe is lazily connected on first packet exchange.
//    The c# host (PacketPipe.cs) creates the named pipe server; this dll is
//    the client. If the pipe isn't available yet (c# side hasn't started),
//    packets pass through unmodified until it connects.
//
// ============================================================================
// PACKET FRAMING
// ============================================================================
//
// The low 2 bits of byte 0 encode the size-header length:
//   bits=0: 1-byte size at offset 1, payload starts at offset 2
//   bits=1: 2-byte size at offset 1, payload starts at offset 3
//   bits=2: 3-byte size at offset 1, payload starts at offset 4
//   bits=3: 4-byte size at offset 1, payload starts at offset 5
//
// The high 4 bits of byte 0 encode the packet type:
//   0 = data (normal game packet)
//   1 = ping
//   2 = pong
//   3 = ackn
//   4 = data (alternate variant)
//
// Only types 0 and 4 carry translatable content. The 3-byte routing key
// lives at the start of the payload (immediately after the size header).

#include <Windows.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <utility>

#pragma comment(lib, "psapi.lib")
#include <psapi.h>

#define PIPE_NAME    L"\\\\.\\pipe\\dqxclarity"

static HINSTANCE g_hInst = NULL;

// ── Logging ──────────────────────────────────────────────────────────────────

static void Log(const char* msg)
{
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(g_hInst, path, MAX_PATH);
    WCHAR* sl = wcsrchr(path, L'\\');
    if (sl) { *sl = L'\0'; sl = wcsrchr(path, L'\\'); }
    if (sl) sl[1] = L'\0'; else path[0] = L'\0';
    lstrcatW(path, L"logs\\packetwarden.log");
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME t;
    GetLocalTime(&t);
    char ts[32];
    wsprintfA(ts, "%04d-%02d-%02d %02d:%02d:%02d ", t.wYear, t.wMonth, t.wDay,
              t.wHour, t.wMinute, t.wSecond);
    DWORD written;
    WriteFile(h, ts, lstrlenA(ts), &written, NULL);
    WriteFile(h, msg, lstrlenA(msg), &written, NULL);
    const char nl = '\n';
    WriteFile(h, &nl, 1, &written, NULL);
    CloseHandle(h);
}

// ── Parser resolver (port of sleep_test.js) ──────────────────────────────────

static const BYTE MODRM_BYTES[] = { 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57 };
static const int  MODRM_COUNT   = sizeof(MODRM_BYTES) / sizeof(MODRM_BYTES[0]);

// Finds every `FF <modrm> <disp>` where modrm encodes a `call dword ptr [reg+disp8]`
// for the common GP registers (skips SIB-encoded base - uncommon for vtable dispatch).
static void ScanIndirectCalls(BYTE* base, SIZE_T size, BYTE disp, std::vector<BYTE*>& out)
{
    if (size < 3) return;
    for (SIZE_T i = 0; i <= size - 3; i++) {
        if (base[i] != 0xFF) continue;
        BYTE modrm = base[i + 1];
        if (base[i + 2] != disp) continue;
        for (int j = 0; j < MODRM_COUNT; j++)
            if (MODRM_BYTES[j] == modrm) { out.push_back(base + i); break; }
    }
}

// Returns TRUE if both 2-byte patterns appear at least once in [start, end).
static BOOL RegionContainsBothPushes(BYTE* start, BYTE* end)
{
    const BYTE p16[2] = { 0x6A, 0x16 };
    const BYTE p1B[2] = { 0x6A, 0x1B };
    BOOL f16 = FALSE, f1B = FALSE;
    if (end <= start || (end - start) < 2) return FALSE;
    for (BYTE* p = start; p + 2 <= end; p++) {
        if (!f16 && p[0] == p16[0] && p[1] == p16[1]) f16 = TRUE;
        if (!f1B && p[0] == p1B[0] && p[1] == p1B[1]) f1B = TRUE;
        if (f16 && f1B) return TRUE;
    }
    return FALSE;
}

// Walk back from a body address through CC padding to find a function prologue.
// MSVC aligns function boundaries with 0xCC (int 3) bytes; the byte after the
// last CC of a padding run is the function start.
static BYTE* FindFunctionStart(BYTE* bodyAddr, BYTE* modBase)
{
    for (int off = 1; off < 0x800; off++) {
        BYTE* p = bodyAddr - off;
        if (p < modBase) return NULL;
        if (*p != 0xCC) continue;
        BYTE* c = p + 1;
        BYTE b0 = c[0];
        BYTE b1 = c[1];
        // recognise the common x86 function prologues
        if ((b0 == 0x55 && b1 == 0x8B) ||               // push ebp; mov ebp, esp
            (b0 == 0x8B && b1 == 0xFF) ||               // mov edi, edi (hotpatch stub)
            b0 == 0x53 || b0 == 0x56 || b0 == 0x57 ||   // push ebx / esi / edi
            (b0 == 0x83 && b1 == 0xEC) ||               // sub esp, imm8
            (b0 == 0x81 && b1 == 0xEC))                 // sub esp, imm32
            return c;
    }
    return NULL;
}

static BYTE* ResolveParser(BYTE* base, SIZE_T size, bool verbose)
{
    char buf[128];

    std::vector<BYTE*> calls5C, calls64;
    ScanIndirectCalls(base, size, 0x5C, calls5C);
    ScanIndirectCalls(base, size, 0x64, calls64);
    if (verbose) {
        wsprintfA(buf, "call [reg+5C] sites = %u, call [reg+64] sites = %u",
                  (unsigned)calls5C.size(), (unsigned)calls64.size());
        Log(buf);
    }

    const SIZE_T WINDOW = 0x300;
    std::vector<std::pair<BYTE*, BYTE*>> pairs;
    for (auto a : calls5C) {
        for (auto b : calls64) {
            SIZE_T diff = (a < b) ? (SIZE_T)(b - a) : (SIZE_T)(a - b);
            if (diff < WINDOW) pairs.push_back(std::make_pair(a, b));
        }
    }
    if (verbose) {
        wsprintfA(buf, "(5C, 64) pairs within 0x%X = %u", (unsigned)WINDOW, (unsigned)pairs.size());
        Log(buf);
    }

    BYTE* modEnd = base + size;
    std::vector<std::pair<BYTE*, BYTE*>> verified;
    for (auto& pr : pairs) {
        BYTE* lo = pr.first < pr.second ? pr.first : pr.second;
        BYTE* hi = pr.first < pr.second ? pr.second : pr.first;
        BYTE* ws = (lo - 0x200) < base   ? base   : (lo - 0x200);
        BYTE* we = (hi + 0x200) > modEnd ? modEnd : (hi + 0x200);
        if (RegionContainsBothPushes(ws, we)) verified.push_back(pr);
    }
    if (verbose) {
        wsprintfA(buf, "verified candidates = %u", (unsigned)verified.size());
        Log(buf);
    }

    if (verified.empty()) return NULL;

    BYTE* a = verified[0].first;
    BYTE* b = verified[0].second;
    BYTE* earliest = (a < b) ? a : b;
    BYTE* entry = FindFunctionStart(earliest, base);
    if (!entry) { Log("could not walk back to function start"); return NULL; }
    wsprintfA(buf, "parser entry @ %p (RVA 0x%X)", entry, (unsigned)(entry - base));
    Log(buf);
    return entry;
}

// ── Minimal x86 length-disassembler for prologue trampolines ─────────────────
//
// Only needs to handle instructions we expect at the start of MSVC-compiled
// functions: push/pop reg, mov reg-reg via modrm, sub esp imm8/imm32,
// xor reg-reg, lea (modrm + optional disp). Returns 0 for unknown opcodes so
// InstallHook can fail loudly and the user pastes the bytes to extend coverage.

static int ModRmSize(BYTE modrm)
{
    int mod = modrm >> 6;
    int rm  = modrm & 7;
    int size = 1; // the modrm byte itself
    int sib  = (mod != 3 && rm == 4) ? 1 : 0;
    size += sib;
    if (mod == 0) {
        if (rm == 5) size += 4;             // [disp32]
        else if (sib) {
            // mod==00 + SIB + base==5 also has disp32; we'd need to peek SIB,
            // which we don't here. Prologue code rarely uses these. Approximate
            // as no-displacement; caller fails noisily if we get it wrong.
        }
    } else if (mod == 1) size += 1;         // disp8
    else if (mod == 2) size += 4;           // disp32
    return size;
}

// Length of a single instruction at `p`. Returns 0 if unknown.
static int InstrLen(const BYTE* p)
{
    int off = 0;
    // Skip operand-size / address-size prefixes
    while (p[off] == 0x66 || p[off] == 0x67) off++;

    BYTE op = p[off];

    // single-byte
    if ((op >= 0x40 && op <= 0x5F) ||       // inc/dec/push/pop reg
        op == 0x90 ||                       // nop
        op == 0xC3 || op == 0xCB ||         // ret near/far
        op == 0xC9 ||                       // leave
        op == 0xCC) return off + 1;         // int3

    // modrm-only ops (opcode + modrm + optional disp)
    static const BYTE MODRM_ONLY[] = {
        0x00, 0x01, 0x02, 0x03,             // add
        0x08, 0x09, 0x0A, 0x0B,             // or
        0x10, 0x11, 0x12, 0x13,             // adc
        0x18, 0x19, 0x1A, 0x1B,             // sbb
        0x20, 0x21, 0x22, 0x23,             // and
        0x28, 0x29, 0x2A, 0x2B,             // sub
        0x30, 0x31, 0x32, 0x33,             // xor
        0x38, 0x39, 0x3A, 0x3B,             // cmp
        0x84, 0x85, 0x86, 0x87,             // test/xchg
        0x88, 0x89, 0x8A, 0x8B,             // mov
        0x8D,                               // lea
        0x8F,                               // pop r/m
        0xFF                                // inc/dec/call/jmp r/m
    };
    for (size_t k = 0; k < sizeof(MODRM_ONLY); k++) {
        if (MODRM_ONLY[k] == op) return off + 1 + ModRmSize(p[off + 1]);
    }

    // modrm + imm8
    if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0xC0 || op == 0xC1 ||
        op == 0x6B)
        return off + 1 + ModRmSize(p[off + 1]) + 1;

    // modrm + imm32
    if (op == 0x81 || op == 0xC7 || op == 0x69)
        return off + 1 + ModRmSize(p[off + 1]) + 4;

    // E8/E9 rel32 call/jmp; EB rel8
    if (op == 0xE8 || op == 0xE9) return off + 5;
    if (op == 0xEB) return off + 2;

    // mov reg, imm32 (B8+r)
    if (op >= 0xB8 && op <= 0xBF) return off + 5;

    return 0;
}

// Copy whole instructions from `src` to `dst` until at least `minBytes` covered.
// Returns the total bytes copied, or 0 if we encountered an unknown opcode
// before reaching the threshold.
static int CopyPrologue(BYTE* dst, BYTE* src, int minBytes)
{
    int copied = 0;
    while (copied < minBytes) {
        int n = InstrLen(src + copied);
        if (n == 0) return 0;
        copied += n;
    }
    memcpy(dst, src, copied);
    return copied;
}

// ── Inline hook installer ────────────────────────────────────────────────────
// Overwrites the first instructions at fn with a 5-byte JMP rel32 to hookFn.
// Allocates an executable trampoline that contains the original prologue
// bytes followed by a JMP back to fn + prologue_len.

static void* InstallHook(BYTE* fn, void* hookFn)
{
    BYTE* tramp = (BYTE*)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return NULL;

    int prologueLen = CopyPrologue(tramp, fn, 5);
    if (prologueLen == 0) {
        char buf[128];
        wsprintfA(buf, "unknown prologue bytes: %02X %02X %02X %02X %02X %02X %02X %02X",
                  fn[0], fn[1], fn[2], fn[3], fn[4], fn[5], fn[6], fn[7]);
        Log(buf);
        VirtualFree(tramp, 0, MEM_RELEASE);
        return NULL;
    }

    // Trampoline tail: JMP fn + prologueLen
    tramp[prologueLen]     = 0xE9;
    *(DWORD*)(tramp + prologueLen + 1) = (DWORD)(fn + prologueLen - (tramp + prologueLen + 5));

    DWORD old;
    VirtualProtect(fn, prologueLen, PAGE_EXECUTE_READWRITE, &old);
    fn[0] = 0xE9;
    *(DWORD*)(fn + 1) = (DWORD)((BYTE*)hookFn - (fn + 5));
    // Fill the bytes between the JMP and the next clean boundary with NOPs so
    // a disassembler walking from fn sees something legal; doesn't matter for
    // execution since we jump out immediately.
    for (int i = 5; i < prologueLen; i++) fn[i] = 0x90;
    VirtualProtect(fn, prologueLen, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fn, prologueLen);

    char buf[64];
    wsprintfA(buf, "hook installed (copied %d prologue bytes)", prologueLen);
    Log(buf);
    return tramp;
}

// ── KNOWN_PACKETS table ──────────────────────────────────────────────────────
//
// Allowlist of packet routing keys that contain translatable content (quest names,
// NPC dialogue, party lists, etc). Only packets whose 3-byte routing key matches
// an entry here get sent to the c# host -- everything else passes through
// untouched, keeping overhead near zero for the vast majority of network traffic.
//
// Each entry is (op_code << 16) | (marker1 << 8) | marker2. These must stay in
// sync with the c# side's DataPacketRouter.

static const uint32_t KNOWN_PACKETS[] = {
    0x21e535, 0x21be01, 0x21a83c, 0x219804, 0x216dd4, 0x5d2b15, 0x5dcc51,
    0x875408, 0x878408, 0x876185, 0x0d9ee1, 0x0dee25, 0x0d2711,
    0x0d7690, 0x0d755d, 0x3d16b6, 0x52ee25, 0x664cc2, 0x66da30,
    0x664569, 0x79994b, 0x03f7f5, 0x035408, 0xa12711, 0xa18a6a,
    0x466bb8, 0x4b4569, 0xa1b121, 0xaade02, 0xaa7a64, 0x052b66,
};
static const int KNOWN_PACKETS_COUNT = sizeof(KNOWN_PACKETS) / sizeof(KNOWN_PACKETS[0]);

static BOOL IsKnownPacket(uint32_t key)
{
    for (int i = 0; i < KNOWN_PACKETS_COUNT; i++)
        if (KNOWN_PACKETS[i] == key) return TRUE;
    return FALSE;
}

// ── Packet dedup ──────────────────────────────────────────────────────────────
//
// Identical packets arriving at high frequency (e.g., entity/party data at
// ~1000/s) would each block the game thread with a sync pipe round-trip even
// though C# returns "no change" every time. The dedup cache suppresses those
// redundant round-trips: if the same (key, len, hash) was piped within the
// last 100ms, skip the pipe and call Orig_ParseNet directly.

static uint32_t Fnv1a(const BYTE* data, uint32_t len)
{
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < len; i++)
        h = (h ^ data[i]) * 16777619u;
    return h;
}

#define DEDUP_SLOTS 64
#define DEDUP_WINDOW_MS 100

struct DedupEntry { uint32_t key; uint32_t len; uint32_t hash; DWORD ticks; };
static DedupEntry       g_dedup[DEDUP_SLOTS];   // zero-initialized by default
static int              g_dedup_pos = 0;
static CRITICAL_SECTION g_dedup_cs;
static BOOL             g_dedup_inited = FALSE;

static void EnsureDedupLock(void)
{
    if (!g_dedup_inited) {
        InitializeCriticalSection(&g_dedup_cs);
        g_dedup_inited = TRUE;
    }
}

// Returns TRUE if the packet is a duplicate of a recent pipe send.
// Inserts the entry (and returns FALSE) when it's new or expired.
static BOOL CheckDedup(uint32_t key, uint32_t len, uint32_t hash)
{
    DWORD now = GetTickCount();
    EnterCriticalSection(&g_dedup_cs);
    for (int i = 0; i < DEDUP_SLOTS; i++) {
        DedupEntry& e = g_dedup[i];
        if (e.key == key && e.len == len && e.hash == hash &&
            (now - e.ticks) < DEDUP_WINDOW_MS) {
            LeaveCriticalSection(&g_dedup_cs);
            return TRUE;
        }
    }
    g_dedup[g_dedup_pos] = { key, len, hash, now };
    g_dedup_pos = (g_dedup_pos + 1) % DEDUP_SLOTS;
    LeaveCriticalSection(&g_dedup_cs);
    return FALSE;
}


// Debug-discovery mode: when the env var DQXCLARITY_FORWARD_ALL is "1", the
// hook forwards EVERY type-0/type-4 data packet to the c# host instead of just
// the KNOWN_PACKETS allowlist. The c# dispatcher returns "unchanged" for any
// packet it doesn't recognise, so behaviour is identical for the game; the
// only difference is the extra pipe round-trips, which let unknown packets
// surface in the debug grid for analysis.
//
// Set by InstallThread once, read by H_ParseNetworkPacket on every call.
static BOOL g_forwardAll = FALSE;

// Per the new resolver (sleep_test.js), the framing's low 2 bits of byte 0 tell
// us where the payload starts: offset = (b0 & 3) + 2.
//   ll=0: 2  (1-byte size header)
//   ll=1: 3  (2-byte size header)
//   ll=2: 4  (3-byte size header)
//   ll=3: 5  (4-byte size header)
static uint32_t ComputeOriginalSize(const BYTE* packet, uint32_t packet_length)
{
    int ll = packet[0] & 3;
    if (packet_length < (uint32_t)(ll + 2)) return 0;
    switch (ll) {
        case 0: return (uint32_t)packet[1] + 2;
        case 1: return (uint32_t)(*(uint16_t*)(packet + 1)) + 3;
        case 2: {
            // 3-byte little-endian size (u24)
            uint32_t v = (uint32_t)packet[1] | ((uint32_t)packet[2] << 8) | ((uint32_t)packet[3] << 16);
            return v + 4;
        }
        case 3: return *(uint32_t*)(packet + 1) + 5;
        default: return 0;
    }
}

// ── Pipe IPC ─────────────────────────────────────────────────────────────────
//
// Communication channel between this dll (inside DQXGame.exe) and the c# host.
// Uses a single named pipe instance. Thread-safe via critical section since the
// game may call the parser from multiple threads concurrently.
//
// The pipe is lazily connected: if the c# host isn't listening yet, packets
// just pass through unmodified until it comes up. If the pipe breaks (c# side
// restarts, game alt-tabs and the host cycles), the next ExchangePacket call
// detects the broken pipe, closes the handle, and reconnects on the following
// attempt.

static HANDLE          g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipe_lock;
static BOOL            g_pipe_inited = FALSE;

static void EnsurePipeLock(void)
{
    if (!g_pipe_inited) {
        InitializeCriticalSection(&g_pipe_lock);
        g_pipe_inited = TRUE;
    }
}

static BOOL TryConnectPipe(void)
{
    if (g_pipe != INVALID_HANDLE_VALUE) return TRUE;
    HANDLE h = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);
    g_pipe = h;
    Log("pipe connected");
    return TRUE;
}

static void ClosePipe(void)
{
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

static BOOL WriteAll(HANDLE h, const void* buf, DWORD len)
{
    DWORD off = 0;
    while (off < len) {
        DWORD wrote = 0;
        if (!WriteFile(h, (const BYTE*)buf + off, len - off, &wrote, NULL) || wrote == 0)
            return FALSE;
        off += wrote;
    }
    return TRUE;
}

static BOOL ReadAll(HANDLE h, void* buf, DWORD len)
{
    DWORD off = 0;
    while (off < len) {
        DWORD got = 0;
        if (!ReadFile(h, (BYTE*)buf + off, len - off, &got, NULL) || got == 0)
            return FALSE;
        off += got;
    }
    return TRUE;
}

// Sends a raw packet to the c# host and receives the (possibly modified) result.
//
// Wire protocol:
//   This dll (client) -> C# host (server):
//     [uint32 packet_length] [packet_length bytes of raw packet data]
//
//   C# host -> This dll:
//     [uint8 modified_flag]
//     If modified_flag == 0: no modification, nothing else follows.
//     If modified_flag == 1: [uint32 new_length] [new_length bytes of translated packet]
//
// Returns TRUE if the c# side sent back a modified packet (out_buf/out_len populated).
// Returns FALSE if unmodified, pipe not connected, or any I/O error. On error the
// pipe is closed so the next call will attempt a fresh connection.
//
// Caller is responsible for HeapFree'ing *out_buf when done.
static BOOL ExchangePacket(const BYTE* in_buf, uint32_t in_len, BYTE** out_buf, uint32_t* out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    EnterCriticalSection(&g_pipe_lock);
    BOOL modified = FALSE;

    // lazy connect -- if the c# host isn't up yet, packet passes through unmodified
    if (!TryConnectPipe()) goto done;

    // send the raw packet to c# for translation
    if (!WriteAll(g_pipe, &in_len, 4)) { ClosePipe(); goto done; }
    if (!WriteAll(g_pipe, in_buf, in_len)) { ClosePipe(); goto done; }

    // read the response: first byte tells us if the packet was modified
    BYTE flag = 0;
    if (!ReadAll(g_pipe, &flag, 1)) { ClosePipe(); goto done; }
    if (flag == 0) goto done;  // c# said "no changes", use original

    // flag == 1: c# has a translated packet for us
    uint32_t new_len = 0;
    if (!ReadAll(g_pipe, &new_len, 4)) { ClosePipe(); goto done; }
    if (new_len == 0 || new_len > 0x100000) { ClosePipe(); goto done; }  // sanity cap 1MB

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, new_len);
    if (!buf) { ClosePipe(); goto done; }
    if (!ReadAll(g_pipe, buf, new_len)) {
        HeapFree(GetProcessHeap(), 0, buf);
        ClosePipe();
        goto done;
    }
    *out_buf = buf;
    *out_len = new_len;
    modified = TRUE;

done:
    LeaveCriticalSection(&g_pipe_lock);
    return modified;
}

// ── ParseNetworkPacket hook ──────────────────────────────────────────────────
//
// Original calling convention: __thiscall (`this` in ECX, rest pushed
// right-to-left, callee cleans the stack). MSVC won't let a free function
// carry __thiscall - only class member functions can. We use __stdcall
// (callee-cleans, same as __thiscall sans the ECX special-case) and capture
// `this` from ECX with inline asm at entry. The function-pointer typedef CAN
// be __thiscall, so we still call back through the trampoline with the correct
// ABI.

typedef int (__thiscall *PFN_ParseNet)(void* thisptr, BYTE* packet_data, unsigned int packet_length);
static PFN_ParseNet Orig_ParseNet = NULL;

// This is the hook function -- every call to the game's packet parser lands here.
//
// It acts as a transparent proxy: for packets we don't care about, it calls
// straight through to the original parser. For known translatable packets, it
// round-trips the data through the c# host (which translates the strings),
// then feeds the translated version to the original parser instead.
//
// The return value is critical for stream integrity -- see "RETURN VALUE" in
// the file header.
static int __stdcall H_ParseNetworkPacket(BYTE* packet_data, unsigned int packet_length)
{
    // Capture the `this` pointer from ECX. The original function is __thiscall
    // (this in ECX), but we're declared __stdcall because MSVC won't allow
    // __thiscall on a free function. We grab ECX manually.
    void* thisptr;
    __asm mov thisptr, ecx

    // ── Filter: decide if this packet needs translation ──

    if (packet_length == 0)
        return Orig_ParseNet(thisptr, packet_data, packet_length);

    // High nibble of byte 0 = packet type.
    // Only types 0 and 4 are data packets with translatable content.
    BYTE first = packet_data[0];
    int type = first >> 4;
    if (type != 0 && type != 4)
        return Orig_ParseNet(thisptr, packet_data, packet_length);

    // Low 2 bits of byte 0 determine size-header length, so payload starts
    // at (low_bits + 2). The first 3 bytes of payload form the routing key.
    int payload_off = (first & 3) + 2;
    if (packet_length < (unsigned int)(payload_off + 3))
        return Orig_ParseNet(thisptr, packet_data, packet_length);

    // Build the 3-byte routing key: (opcode << 16) | (marker1 << 8) | marker2.
    // This uniquely identifies the packet type (quest data, npc dialogue, etc).
    uint32_t key = ((uint32_t)packet_data[payload_off]     << 16)
                 | ((uint32_t)packet_data[payload_off + 1] << 8)
                 |  (uint32_t)packet_data[payload_off + 2];


    // Not in our table of known translatable packets -- pass through, UNLESS
    // debug-discovery mode is on (env var DQXCLARITY_FORWARD_ALL=1), in which
    // case we forward everything so unknown packets surface in the c# debug
    // grid. The c# dispatcher returns no modification for unknown packets, so
    // game behaviour is unchanged.
    if (!IsKnownPacket(key) && !g_forwardAll)
        return Orig_ParseNet(thisptr, packet_data, packet_length);

    // ── Dedup: skip pipe for identical packets seen within the last 100ms ──
    uint32_t pkt_hash = Fnv1a(packet_data, packet_length);
    if (CheckDedup(key, packet_length, pkt_hash))
        return Orig_ParseNet(thisptr, packet_data, packet_length);

    // ── Translate: round-trip through the c# host ──

    // Save the original packet's declared size BEFORE any modification.
    // We need this for the return value (stream cursor advancement).
    uint32_t original_size = ComputeOriginalSize(packet_data, packet_length);

    // Send to c# host over the named pipe; get back translated bytes (or nothing).
    BYTE* new_buf = NULL;
    uint32_t new_len = 0;
    BOOL modified = ExchangePacket(packet_data, packet_length, &new_buf, &new_len);

    // ── Feed the game: call the original parser with (possibly translated) data ──

    if (modified && new_buf) {
        // c# translated the packet -- feed the modified version to the game.
        // The game's parser processes the translated strings as if they came
        // from the server.
        Orig_ParseNet(thisptr, new_buf, new_len);
        HeapFree(GetProcessHeap(), 0, new_buf);
    } else {
        // No translation (pipe down, unknown packet, or c# returned flag=0).
        Orig_ParseNet(thisptr, packet_data, packet_length);
    }

    // ── Return the ORIGINAL size, not the modified size ──
    //
    // The game's network layer uses this return value to advance its read
    // cursor through the receive buffer. The receive buffer still contains
    // the original (untranslated) bytes from the server. If we returned
    // new_len (the translated size), the cursor would over- or under-shoot
    // and land in the middle of the next packet, desyncing the entire stream
    // and crashing the game.
    return (int)(original_size != 0 ? original_size : packet_length);
}

// ── Install thread ───────────────────────────────────────────────────────────
//
// Runs on a background thread (not DllMain) because DllMain runs under the
// loader lock, where calling most Win32 APIs is unsafe. This thread does the
// heavy lifting: finds the parser function by scanning memory, then patches it.
//
// Retries up to 10 times with 1s delays because the game's code section may
// not be fully unpacked/loaded at the moment we're injected.

static DWORD WINAPI InstallThread(LPVOID arg)
{
    (void)arg;

    // Get the base address and size of the main game executable in memory.
    HMODULE main_mod = GetModuleHandleW(NULL);
    if (!main_mod) { Log("GetModuleHandleW(NULL) failed"); return 1; }

    MODULEINFO mi = {0};
    if (!GetModuleInformation(GetCurrentProcess(), main_mod, &mi, sizeof(mi))) {
        Log("GetModuleInformation failed");
        return 1;
    }

    // Pick up the debug-discovery flag once at install time. Cheaper than
    // reading the env var on every packet (this hook is on a hot path).
    char envVal[8] = {0};
    DWORD envLen = GetEnvironmentVariableA("DQXCLARITY_FORWARD_ALL", envVal, sizeof(envVal));
    if (envLen > 0 && envVal[0] == '1') {
        g_forwardAll = TRUE;
        Log("DQXCLARITY_FORWARD_ALL=1 - forwarding ALL data packets to c# host (debug-discovery mode)");
    }

    // Scan the game's memory for the parser function's body fingerprint.
    // Only logs verbose details on the last attempt to avoid log spam.
    const int MAX_ATTEMPTS = 10;
    Log("scanning for parser body fingerprint");
    BYTE* entry = NULL;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        bool last = (attempt == MAX_ATTEMPTS);
        entry = ResolveParser((BYTE*)mi.lpBaseOfDll, mi.SizeOfImage, last);
        if (entry) break;
        if (!last) Sleep(1000);
    }
    if (!entry) {
        Log("parser body fingerprint not found - investigate; VCE base class may have changed");
        return 1;
    }

    // Found the parser -- install the inline hook. After this returns,
    // Orig_ParseNet points to the trampoline (which calls the original),
    // and the parser's entry point now JMPs to H_ParseNetworkPacket.
    EnsurePipeLock();
    EnsureDedupLock();
    void* trampoline = InstallHook(entry, (void*)H_ParseNetworkPacket);
    if (!trampoline) { Log("InstallHook failed"); return 1; }
    Orig_ParseNet = (PFN_ParseNet)trampoline;
    return 0;
}

// ── DllMain ──────────────────────────────────────────────────────────────────
//
// Entry point when the dll is injected into DQXGame.exe. All real work happens
// on a background thread (InstallThread) because DllMain runs under the loader
// lock where most interesting Win32 calls are forbidden.
//
// extern "C" so MSVC doesn't mangle the export when this file builds as c++.

extern "C" BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInst = hInst;
        DisableThreadLibraryCalls(hInst);
        // Kick off the install thread -- it will find the parser and hook it.
        HANDLE h = CreateThread(NULL, 0, InstallThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
