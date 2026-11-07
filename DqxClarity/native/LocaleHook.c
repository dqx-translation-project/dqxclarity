#include <Windows.h>
#include <string.h>
#include <imm.h>

static HINSTANCE g_hInst = NULL;

// ── Locale constant stubs ─────────────────────────────────────────────────────
static UINT   WINAPI H_GetACP(void)                     { return 932;    }
static UINT   WINAPI H_GetOEMCP(void)                   { return 932;    }
static LCID   WINAPI H_GetUserDefaultLCID(void)         { return 0x0411; }
static LCID   WINAPI H_GetSystemDefaultLCID(void)       { return 0x0411; }
static LANGID WINAPI H_GetUserDefaultUILanguage(void)   { return 0x0411; }
static LANGID WINAPI H_GetSystemDefaultUILanguage(void) { return 0x0411; }
static LANGID WINAPI H_GetUserDefaultLangID(void)       { return 0x0411; }

// ── Conversion hooks: redirect CP_ACP/CP_OEMCP → 932 ─────────────────────────
typedef int (WINAPI *PFN_MBTWC)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int (WINAPI *PFN_WCTMB)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);

static PFN_MBTWC Orig_MultiByteToWideChar = NULL;
static PFN_WCTMB Orig_WideCharToMultiByte = NULL;

static int WINAPI H_MultiByteToWideChar(UINT cp, DWORD flags, LPCCH mb, int cbMb, LPWSTR wc, int cchWc)
{
    if (cp == CP_ACP || cp == CP_OEMCP) {
        // Clipboard paste sends UTF-8; Shift-JIS lead bytes (0x81-0x9F, 0xE0-0xFC) are
        // never valid UTF-8 starts, so this disambiguates without false positives.
        int r = Orig_MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, mb, cbMb, wc, cchWc);
        if (r > 0) return r;
        cp = 932;
    }
    return Orig_MultiByteToWideChar(cp, flags, mb, cbMb, wc, cchWc);
}

static int WINAPI H_WideCharToMultiByte(UINT cp, DWORD flags, LPCWSTR wc, int cchWc,
                                         LPSTR mb, int cbMb, LPCSTR def, LPBOOL used)
{
    if (cp == CP_ACP || cp == CP_OEMCP) cp = 932;
    return Orig_WideCharToMultiByte(cp, flags, wc, cchWc, mb, cbMb, def, used);
}

// ── Inline hook (no trampoline — original not needed) ────────────────────────
static void InlineHook(HMODULE mod, const char* name, void* hookFn)
{
    BYTE* fn = (BYTE*)GetProcAddress(mod, name);
    if (!fn) return;
    DWORD old;
    VirtualProtect(fn, 5, PAGE_EXECUTE_READWRITE, &old);
    fn[0] = 0xE9;
    *(DWORD*)(fn + 1) = (DWORD)((BYTE*)hookFn - fn - 5);
    VirtualProtect(fn, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fn, 5);
}

// Patches fn, returns a trampoline that calls the original.
// Trampoline layout: [5 original bytes] + [JMP fn+5]
static void* InlineHookWithTrampoline(HMODULE mod, const char* name, void* hookFn)
{
    BYTE* fn = (BYTE*)GetProcAddress(mod, name);
    if (!fn) return NULL;

    BYTE* t = (BYTE*)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!t) return NULL;
    memcpy(t, fn, 5);
    t[5] = 0xE9;
    *(DWORD*)(t + 6) = (DWORD)(fn + 5 - (t + 10));

    DWORD old;
    VirtualProtect(fn, 5, PAGE_EXECUTE_READWRITE, &old);
    fn[0] = 0xE9;
    *(DWORD*)(fn + 1) = (DWORD)((BYTE*)hookFn - fn - 5);
    VirtualProtect(fn, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), fn, 5);
    return t;
}

static void WriteLog(const char* msg)
{
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(g_hInst, path, MAX_PATH);
    WCHAR* sl = wcsrchr(path, L'\\');
    if (sl) { *sl = L'\0'; sl = wcsrchr(path, L'\\'); }
    if (sl) sl[1] = L'\0'; else path[0] = L'\0';
    lstrcatW(path, L"logs\\localehook.log");
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
    CloseHandle(h);
}

// ── Paste support ─────────────────────────────────────────────────────────────

static HWND    g_gameHwnd    = NULL;
static WNDPROC g_origWndProc = NULL;
static BOOL    g_unicodeWnd  = FALSE;

static void PasteClipboardText(HWND hwnd)
{
    if (!OpenClipboard(hwnd)) return;

    HANDLE hMem = GetClipboardData(CF_UNICODETEXT);
    if (!hMem) { CloseClipboard(); return; }

    WCHAR *wtext = (WCHAR *)GlobalLock(hMem);
    if (!wtext || !wtext[0]) { GlobalUnlock(hMem); CloseClipboard(); return; }

    // Inject via IME composition — the same path the Japanese IME uses when the user
    // types normally. WM_IME_COMPOSITION fires with GCS_RESULTSTR; the game reads
    // the Unicode result and converts it to UTF-8 for the chat buffer.
    // Falls back to WM_CHAR for ASCII when no IME context is available.
    int wlen = lstrlenW(wtext);
    HIMC hImc = ImmGetContext(hwnd);
    if (hImc) {
        ImmSetCompositionStringW(hImc, SCS_SETSTR, wtext, (DWORD)(wlen * sizeof(WCHAR)), NULL, 0);
        ImmNotifyIME(hImc, NI_COMPOSITIONSTR, CPS_COMPLETE, 0);
        ImmReleaseContext(hwnd, hImc);
    } else {
        for (int i = 0; i < wlen; i++) {
            if (wtext[i] <= 0x7E)
                PostMessage(hwnd, WM_CHAR, (WPARAM)wtext[i], 1);
        }
    }

    GlobalUnlock(hMem);
    CloseClipboard();
}

static LRESULT CALLBACK PasteWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    // Intercept Ctrl+V keydown (bit 31 of lParam = 0 means key is being pressed).
    // Suppress default handling so the game doesn't see the raw V keydown.
    if (msg == WM_KEYDOWN && wParam == 'V' && !(lParam >> 31) &&
        (GetKeyState(VK_CONTROL) & 0x8000) && !(GetKeyState(VK_SHIFT) & 0x8000))
    {
        PasteClipboardText(hwnd);
        return 0;
    }

    // Remove subclass when the window is being destroyed.
    if (msg == WM_NCDESTROY) {
        if (g_unicodeWnd)
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)g_origWndProc);
        else
            SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)g_origWndProc);
        g_gameHwnd = NULL;
    }

    return g_unicodeWnd
        ? CallWindowProcW(g_origWndProc, hwnd, msg, wParam, lParam)
        : CallWindowProcA(g_origWndProc, hwnd, msg, wParam, lParam);
}

typedef struct { DWORD pid; HWND hwnd; } FindData;

static BOOL CALLBACK FindMainWindow(HWND hwnd, LPARAM lParam)
{
    FindData *fd = (FindData *)lParam;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != fd->pid || !IsWindowVisible(hwnd)) return TRUE;

    // Skip IME and system helper windows.
    char cls[64];
    GetClassNameA(hwnd, cls, sizeof(cls));
    if (lstrcmpiA(cls, "IME") == 0 || lstrcmpiA(cls, "MSCTFIME UI") == 0) return TRUE;

    // Skip anything too small to be the game surface.
    RECT r = {0};
    GetWindowRect(hwnd, &r);
    if ((r.right - r.left) < 300 || (r.bottom - r.top) < 200) return TRUE;

    fd->hwnd = hwnd;
    return FALSE;
}

static DWORD WINAPI WatchThread(LPVOID unused)
{
    DWORD pid = GetCurrentProcessId();
    FindData fd;

    // The game window may not exist yet at DLL load time; poll until it appears.
    for (;;) {
        Sleep(200);
        fd.pid  = pid;
        fd.hwnd = NULL;
        EnumWindows(FindMainWindow, (LPARAM)&fd);
        if (fd.hwnd) break;
    }

    g_gameHwnd   = fd.hwnd;
    g_unicodeWnd = IsWindowUnicode(g_gameHwnd);

    if (g_unicodeWnd) {
        g_origWndProc = (WNDPROC)(LONG_PTR)GetWindowLongPtrW(g_gameHwnd, GWLP_WNDPROC);
        SetWindowLongPtrW(g_gameHwnd, GWLP_WNDPROC, (LONG_PTR)PasteWndProc);
    } else {
        g_origWndProc = (WNDPROC)(LONG_PTR)GetWindowLongPtrA(g_gameHwnd, GWLP_WNDPROC);
        SetWindowLongPtrA(g_gameHwnd, GWLP_WNDPROC, (LONG_PTR)PasteWndProc);
    }

    char logmsg[128];
    wsprintfA(logmsg, "[LocaleHook] paste hook on HWND %p (unicode=%d)\r\n",
              (void *)g_gameHwnd, (int)g_unicodeWnd);
    WriteLog(logmsg);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────

typedef struct { const char* name; void* hook; } HookDef;

static const HookDef k_locale_hooks[] = {
    { "GetACP",                     H_GetACP                    },
    { "GetOEMCP",                   H_GetOEMCP                  },
    { "GetUserDefaultLCID",         H_GetUserDefaultLCID        },
    { "GetSystemDefaultLCID",       H_GetSystemDefaultLCID      },
    { "GetUserDefaultUILanguage",   H_GetUserDefaultUILanguage  },
    { "GetSystemDefaultUILanguage", H_GetSystemDefaultUILanguage},
    { "GetUserDefaultLangID",       H_GetUserDefaultLangID      },
};

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInst = hInst;
        DisableThreadLibraryCalls(hInst);

        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        HMODULE kb  = GetModuleHandleA("kernelbase.dll");

        // Locale stubs — no trampoline needed, we never call through
        int n = (int)(sizeof(k_locale_hooks) / sizeof(k_locale_hooks[0]));
        for (int i = 0; i < n; i++) {
            if (k32) InlineHook(k32, k_locale_hooks[i].name, k_locale_hooks[i].hook);
            if (kb)  InlineHook(kb,  k_locale_hooks[i].name, k_locale_hooks[i].hook);
        }

        // Conversion hooks — patch kernelbase (real impl on Win8+); trampoline calls original
        HMODULE impl = kb ? kb : k32;
        Orig_MultiByteToWideChar = (PFN_MBTWC)InlineHookWithTrampoline(impl, "MultiByteToWideChar", H_MultiByteToWideChar);
        Orig_WideCharToMultiByte = (PFN_WCTMB)InlineHookWithTrampoline(impl, "WideCharToMultiByte", H_WideCharToMultiByte);

        // If kernel32 exports aren't forwarders to the same address, patch them too
        if (k32 && kb) {
            if (GetProcAddress(k32, "MultiByteToWideChar") != GetProcAddress(kb, "MultiByteToWideChar"))
                InlineHook(k32, "MultiByteToWideChar", H_MultiByteToWideChar);
            if (GetProcAddress(k32, "WideCharToMultiByte") != GetProcAddress(kb, "WideCharToMultiByte"))
                InlineHook(k32, "WideCharToMultiByte", H_WideCharToMultiByte);
        }

        char msg[256];
        wsprintfA(msg, "[LocaleHook] pid=%lu GetACP=%u MBTWC=%s WCTMB=%s\r\n",
                  GetCurrentProcessId(), GetACP(),
                  Orig_MultiByteToWideChar ? "ok" : "FAIL",
                  Orig_WideCharToMultiByte ? "ok" : "FAIL");
        WriteLog(msg);

        // Spawn background thread to subclass the game window once it appears.
        HANDLE t = CreateThread(NULL, 0, WatchThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
