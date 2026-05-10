#include <Windows.h>
#include <string.h>

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
    if (cp == CP_ACP || cp == CP_OEMCP) cp = 932;
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
    }
    return TRUE;
}
