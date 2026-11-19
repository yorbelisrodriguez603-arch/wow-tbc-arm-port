#include "shim_api.h"
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace shims {

static std::vector<ShimEntry> g_entries;
static uint32_t g_next_sentinel = SENTINEL_BASE;
static std::unordered_map<std::string, uint32_t> g_mod_cache;

void reset_registry() {
    g_entries.clear();
    g_mod_cache.clear();
    g_next_sentinel = SENTINEL_BASE;
}

uint32_t register_shim(const char* dll, const char* func, int nargs, ShimFn fn) {
    std::string s_dll = dll ? dll : "";
    std::string s_func = func ? func : "";
    for (auto& e : g_entries) {
        if (e.dll == s_dll && e.func == s_func) {
            if (fn) e.fn = fn;
            e.nargs = nargs;
            return e.sentinel;
        }
    }
    uint32_t s = g_next_sentinel;
    g_next_sentinel += 0x10u;
    g_entries.push_back(ShimEntry{s, s_dll, s_func, nargs, fn});
    return s;
}

static int infer_nargs(const std::string& func, int fallback) {
    if (func == "TlsAlloc" || func == "GetLastError" ||
        func == "GetCurrentThreadId" || func == "GetCurrentProcessId" ||
        func == "GetCurrentProcess" || func == "GetCurrentThread" ||
        func == "GetCommandLineA" || func == "GetCommandLineW" ||
        func == "GetEnvironmentStrings" || func == "GetEnvironmentStringsW" ||
        func == "IsDebuggerPresent" || func == "GetTickCount" ||
        func == "GetProcessHeap" ||
        func == "GetForegroundWindow") {
        return 0;
    }
    if (func == "InitializeCriticalSection" ||
        func == "DeleteCriticalSection" ||
        func == "EnterCriticalSection" ||
        func == "LeaveCriticalSection" ||
        func == "GetModuleHandleA" ||
        func == "GetModuleHandleW" ||
        func == "LoadLibraryA" ||
        func == "LoadLibraryW" ||
        func == "FreeLibrary" ||
        func == "CloseHandle" ||
        func == "GetStdHandle" ||
        func == "SetLastError" ||
        func == "SetHandleCount" ||
        func == "GetFileType" ||
        func == "Sleep" ||
        func == "ExitProcess" ||
        func == "IsProcessorFeaturePresent" ||
        func == "HeapDestroy" ||
        func == "TlsGetValue" ||
        func == "GetVersionExA" ||
        func == "GetVersionExW" ||
        func == "GetSystemTimeAsFileTime" ||
        func == "FreeEnvironmentStringsA" ||
        func == "FreeEnvironmentStringsW" ||
        func == "SetUnhandledExceptionFilter" ||
        func == "UnhandledExceptionFilter" ||
        func == "QueryPerformanceCounter" ||
        func == "GetStartupInfoA" ||
        func == "GetStartupInfoW" ||
        func == "GetSystemInfo") {
        return 1;
    }
    if (func == "GetProcAddress" || func == "IsBadReadPtr" || func == "GetConsoleMode" || func == "WaitForSingleObject" ||
        func == "TlsSetValue" ||
        func == "" ||
        func == "InitializeCriticalSectionAndSpinCount" ||
        func == "VirtualFree" ||
        func == "InterlockedExchange" ||
        func == "InterlockedIncrement" ||
        func == "InterlockedDecrement") {
        if (func == "InterlockedIncrement" || func == "InterlockedDecrement") return 1;
        return 2;
    }
    if (func == "HeapCreate" || func == "HeapAlloc" || func == "HeapSize" || func == "CreateMutexA" || func == "OpenProcessToken" ||
        func == "GetModuleFileNameA" || func == "GetModuleFileNameW" ||
        func == "InterlockedCompareExchange") {
        return 3;
    }
    if (func == "HeapFree" || func == "HeapReAlloc" || func == "VirtualAlloc" || func == "CreateEventA") {
        return 4;
    }
        if (func == "RegOpenKeyExA" || func == "GetTokenInformation") return 5;
    if (func == "RegQueryValueExA") return 6;
    if (func == "AllocateAndInitializeSid") return 11;
    if (func == "WriteFile") return 5;
    if (func == "CreateThread") return 6;
    if (func == "FormatMessageA") return 7;
    return fallback;
}

uint32_t register_or_get(const char* dll, const char* func, int default_nargs, ShimFn fn, uint32_t* stubbed_out) {
    std::string s_dll = dll ? dll : "";
    std::string s_func = func ? func : "";
    int nargs = infer_nargs(s_func, default_nargs);
    for (auto& e : g_entries) {
        if (e.func == s_func) {
            if (!e.fn && fn) e.fn = fn;
            if (!e.fn && stubbed_out) (*stubbed_out)++;
            return e.sentinel;
        }
    }
    if (!fn && stubbed_out) (*stubbed_out)++;
    return register_shim(s_dll.c_str(), s_func.c_str(), nargs, fn);
}

const ShimEntry* find_by_sentinel(uint32_t sentinel) {
    for (const auto& e : g_entries) {
        if (e.sentinel == sentinel) return &e;
    }
    return nullptr;
}

static uint32_t get_or_create_mod(emu::RuntimeState& st, const std::string& name, const char* tag) {
    if (name.empty()) return 0x00400000u;
    auto it = g_mod_cache.find(name);
    if (it != g_mod_cache.end()) return it->second;

    uint32_t mod_base = emu::alloc_mem(st, 0x1000u);
    if (mod_base) emu::wr32(st, mod_base, 0x00905A4Du);
    uint32_t h = mod_base ? mod_base : 0x00400000u;
    g_mod_cache[name] = h;
    if (g_mod_cache.size() <= 25) {
        std::printf("  [%s] '%s' -> 0x%x\n", tag, name.c_str(), h);
    }
    return h;
}

static uint32_t shim_GetModuleHandleA(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t lpName = args ? args[0] : 0;
    if (!lpName) return 0x00400000u;
    std::string name = emu::rd_str(st, lpName, 128);
    return get_or_create_mod(st, name, "GetModuleHandleA");
}

static uint32_t shim_LoadLibraryA(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t lpFileName = args ? args[0] : 0;
    if (!lpFileName) return 0;
    std::string name = emu::rd_str(st, lpFileName, 128);
    std::string lower = name;
    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower.find("unicows") != std::string::npos) {
        std::printf("  [LoadLibraryA] '%s' -> 0 (skip MSLU on NT)\n", name.c_str());
        return 0u;
    }
    return get_or_create_mod(st, name, "LoadLibraryA");
}

static uint32_t shim_GetProcAddress(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t lpProcName = args ? args[1] : 0;
    std::string proc = (lpProcName > 0xFFFFu) ? emu::rd_str(st, lpProcName, 128) : "";
    static int gpa_logs = 0;
    if (gpa_logs < 25) {
        std::printf("  [GetProcAddress] proc='%s' (ord=0x%x)\n", proc.c_str(), lpProcName);
        gpa_logs++;
    }
    return register_or_get("KERNEL32.dll", proc.empty() ? "OrdProc" : proc.c_str(), 2, nullptr, nullptr);
}

static uint32_t shim_TlsAlloc(emu::RuntimeState&, const uint32_t*) {
    static uint32_t idx = 1;
    return idx++;
}

static uint32_t shim_TlsGetValue(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t idx = args ? args[0] : 0;
    return (idx < 64) ? st.tls_slots[idx] : 0;
}

static uint32_t shim_TlsSetValue(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t idx = args ? args[0] : 0;
    uint32_t val = args ? args[1] : 0;
    if (idx < 64) {
        st.tls_slots[idx] = val;
        return 1;
    }
    return 0;
}

static uint32_t shim_GetCommandLineA(emu::RuntimeState& st, const uint32_t*) {
    static uint32_t cmd_ptr = 0;
    if (!cmd_ptr) cmd_ptr = emu::alloc_str(st, "Wow.exe");
    return cmd_ptr;
}

static uint32_t shim_GetVersionExA(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t lpVer = args ? args[0] : 0;
    if (!lpVer) return 0;
    uint32_t sz = emu::rd32(st, lpVer);
    if (sz >= 148u) {
        emu::wr32(st, lpVer + 0x04u, 5u);
        emu::wr32(st, lpVer + 0x08u, 1u);
        emu::wr32(st, lpVer + 0x0Cu, 2600u);
        emu::wr32(st, lpVer + 0x10u, 2u);
    }
    return 1;
}

static uint32_t shim_GetModuleFileNameA(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t buf = args ? args[1] : 0;
    uint32_t sz = args ? args[2] : 0;
    const char* exe_path = "C:\\WoW\\Wow.exe";
    size_t len = std::strlen(exe_path);
    if (buf && sz > 0) {
        size_t copy_n = len < (size_t)sz - 1 ? len : (size_t)sz - 1;
        uc_mem_write(st.uc, buf, exe_path, copy_n);
        uint8_t zero = 0;
        uc_mem_write(st.uc, buf + copy_n, &zero, 1);
        return (uint32_t)copy_n;
    }
    return (uint32_t)len;
}

static uint32_t shim_GetStartupInfoA(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t lpSi = args ? args[0] : 0;
    if (lpSi) {
        for (uint32_t off = 0; off < 68u; off += 4u) {
            emu::wr32(st, lpSi + off, 0u);
        }
        emu::wr32(st, lpSi, 68u);
    }
    return 0u;
}

static uint32_t shim_QueryPerformanceCounter(emu::RuntimeState& st, const uint32_t* args) {
    static uint64_t counter = 100000ULL;
    counter += 500ULL;
    uint32_t lpCount = args ? args[0] : 0;
    if (lpCount) {
        emu::wr32(st, lpCount, static_cast<uint32_t>(counter & 0xFFFFFFFFULL));
        emu::wr32(st, lpCount + 4u, static_cast<uint32_t>(counter >> 32));
    }
    return 1u;
}

static uint32_t shim_InterlockedExchange(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t target = args ? args[0] : 0;
    uint32_t val = args ? args[1] : 0;
    if (!target) return 0u;
    uint32_t prev = emu::rd32(st, target);
    emu::wr32(st, target, val);
    return prev;
}

static uint32_t shim_GetProcessHeap(emu::RuntimeState& st, const uint32_t*) {
    static uint32_t proc_heap = 0;
    if (!proc_heap) {
        proc_heap = emu::alloc_mem(st, 0x10000u);
        if (!proc_heap) proc_heap = 0x15000000u;
    }
    return proc_heap;
}

static uint32_t shim_GetCurrentProcess(emu::RuntimeState&, const uint32_t*) {
    return 0xFFFFFFFFu;
}

static uint32_t shim_GetCurrentThreadId(emu::RuntimeState&, const uint32_t*) {
    return 1001u;
}

static uint32_t shim_GetCurrentProcessId(emu::RuntimeState&, const uint32_t*) {
    return 2002u;
}

static uint32_t shim_GetLastError(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_SetLastError(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_IsDebuggerPresent(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_HeapCreate(emu::RuntimeState& st, const uint32_t*) {
    uint32_t h = emu::alloc_mem(st, 0x10000u);
    return h ? h : 0x15000000u;
}

static uint32_t shim_HeapAlloc(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t sz = args ? args[2] : 0x1000u;
    if (sz == 0) sz = 0x10u;
    return emu::alloc_mem(st, sz);
}

static uint32_t shim_HeapSize(emu::RuntimeState&, const uint32_t* args) {
    uint32_t ptr = args ? args[2] : 0u;
    return ptr ? 0x1000u : 0u;
}

static uint32_t shim_HeapReAlloc(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t old_ptr = args ? args[2] : 0u;
    uint32_t new_sz = args ? args[3] : 0x1000u;
    if (new_sz == 0u) new_sz = 0x10u;
    uint32_t new_ptr = emu::alloc_mem(st, new_sz);
    if (new_ptr && old_ptr) {
        size_t copy_sz = new_sz < 0x1000u ? new_sz : 0x1000u;
        uint8_t buf[0x1000];
        if (uc_mem_read(st.uc, old_ptr, buf, copy_sz) == UC_ERR_OK) {
            uc_mem_write(st.uc, new_ptr, buf, copy_sz);
        }
    }
    return new_ptr;
}

static uint32_t shim_HeapFree(emu::RuntimeState&, const uint32_t*) {
    return 1u;
}

static uint32_t shim_VirtualAlloc(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t sz = args ? args[1] : 0x1000u;
    if (sz == 0) sz = 0x1000u;
    return emu::alloc_mem(st, sz);
}


static uint32_t shim_GetTickCount(emu::RuntimeState&, const uint32_t*) {
    static uint32_t ticks = 1000u;
    ticks += 16u;
    return ticks;
}

static uint32_t shim_GetSystemTimeAsFileTime(emu::RuntimeState& st, const uint32_t* args) {
    static uint64_t ft = 116444736000000000ULL;
    ft += 100000ULL;
    uint32_t lpFt = args ? args[0] : 0;
    if (lpFt) {
        emu::wr32(st, lpFt, static_cast<uint32_t>(ft & 0xFFFFFFFFULL));
        emu::wr32(st, lpFt + 4u, static_cast<uint32_t>(ft >> 32));
    }
    return 0u;
}

static uint32_t shim_CritSecNoop(emu::RuntimeState&, const uint32_t*) {
    return 1u;
}


static uint32_t shim_InterlockedIncrement(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t target = args ? args[0] : 0;
    if (!target) return 0u;
    uint32_t v = emu::rd32(st, target) + 1u;
    emu::wr32(st, target, v);
    return v;
}

static uint32_t shim_InterlockedDecrement(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t target = args ? args[0] : 0;
    if (!target) return 0u;
    uint32_t v = emu::rd32(st, target) - 1u;
    emu::wr32(st, target, v);
    return v;
}


static uint32_t shim_GetStdHandle(emu::RuntimeState&, const uint32_t* args) {
    uint32_t n = args ? args[0] : 0;
    if (n == 0xFFFFFFF6u) return 0x10u; // STD_INPUT_HANDLE
    if (n == 0xFFFFFFF5u) return 0x11u; // STD_OUTPUT_HANDLE
    if (n == 0xFFFFFFF4u) return 0x12u; // STD_ERROR_HANDLE
    return 0x10u;
}

static uint32_t shim_SetHandleCount(emu::RuntimeState&, const uint32_t* args) {
    uint32_t cnt = args ? args[0] : 0;
    return cnt ? cnt : 32u;
}


static uint32_t shim_GetACP(emu::RuntimeState&, const uint32_t*) {
    return 1252u;
}

static uint32_t shim_ExitProcess(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t code = args ? args[0] : 0u;
    std::printf("[ExitProcess] uExitCode=%u (0x%x)\n", code, code);
    if (st.uc) {
        uc_emu_stop(st.uc);
    }
    return 0u;
}

static uint32_t shim_GetEnvironmentStrings(emu::RuntimeState& st, const uint32_t*) {
    static uint32_t env_block = 0u;
    if (!env_block) {
        env_block = emu::alloc_mem(st, 0x100u);
        const char env_data[] = "PATH=C:\\Windows\\System32\0";
        for (size_t i = 0; i < sizeof(env_data); ++i) {
            uint8_t b = static_cast<uint8_t>(env_data[i]);
            uc_mem_write(st.uc, env_block + i, &b, 1);
        }
        uint8_t zero = 0u;
        uc_mem_write(st.uc, env_block + sizeof(env_data), &zero, 1);
    }
    return env_block;
}

static uint32_t shim_GetEnvironmentStringsW(emu::RuntimeState& st, const uint32_t*) {
    static uint32_t wenv_block = 0u;
    if (!wenv_block) {
        wenv_block = emu::alloc_mem(st, 0x100u);
        uint8_t zeros[4] = {0, 0, 0, 0};
        uc_mem_write(st.uc, wenv_block, zeros, sizeof(zeros));
    }
    return wenv_block;
}

static uint32_t shim_CreateEventA(emu::RuntimeState&, const uint32_t*) {
    static uint32_t next_ev = 0x2000u;
    next_ev += 4u;
    return next_ev;
}

static uint32_t shim_FreeEnvironmentStringsA(emu::RuntimeState&, const uint32_t*) {
    return 1u;
}

static uint32_t shim_SetUnhandledExceptionFilter(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_GetSystemInfo(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t dst = args ? args[0] : 0u;
    if (dst) {
        uint8_t sysinfo[36] = {0};
        // wProcessorArchitecture (0 = x86), wReserved (0) -> offset 0..3 = 0
        // dwPageSize = 0x1000 -> offset 4
        sysinfo[4] = 0x00; sysinfo[5] = 0x10;
        // lpMinimumApplicationAddress = 0x00010000 -> offset 8
        sysinfo[10] = 0x01;
        // lpMaximumApplicationAddress = 0x7FFEFFFF -> offset 12
        sysinfo[12] = 0xFF; sysinfo[13] = 0xFF; sysinfo[14] = 0xFE; sysinfo[15] = 0x7F;
        // dwActiveProcessorMask = 1 -> offset 16
        sysinfo[16] = 0x01;
        // dwNumberOfProcessors = 1 -> offset 20
        sysinfo[20] = 0x01;
        // dwProcessorType = 586 (0x024A) -> offset 24
        sysinfo[24] = 0x4A; sysinfo[25] = 0x02;
        // dwAllocationGranularity = 0x10000 -> offset 28
        sysinfo[30] = 0x01;
        // wProcessorLevel = 6, wProcessorRevision = 0x0101 -> offset 32..35
        sysinfo[32] = 0x06;
        sysinfo[34] = 0x01; sysinfo[35] = 0x01;
        uc_mem_write(st.uc, dst, sysinfo, sizeof(sysinfo));
    }
    return 0u;
}

static uint32_t shim_CreateMutexA(emu::RuntimeState&, const uint32_t*) {
    static uint32_t next_mtx = 0x3000u;
    next_mtx += 4u;
    return next_mtx;
}

static uint32_t shim_IsBadReadPtr(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_RegOpenKeyExA(emu::RuntimeState&, const uint32_t*) {
    return 2u; // ERROR_FILE_NOT_FOUND
}

static uint32_t shim_RegQueryValueExA(emu::RuntimeState&, const uint32_t*) {
    return 2u; // ERROR_FILE_NOT_FOUND
}

static uint32_t shim_RegCloseKey(emu::RuntimeState&, const uint32_t*) {
    return 0u; // ERROR_SUCCESS
}

static uint32_t shim_AllocateAndInitializeSid(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t sid_addr = emu::alloc_mem(st, 0x40u);
    if (args && args[10]) {
        emu::wr32(st, args[10], sid_addr);
    }
    return sid_addr ? 1u : 0u;
}

static uint32_t shim_OpenProcessToken(emu::RuntimeState& st, const uint32_t* args) {
    if (args && args[2]) {
        emu::wr32(st, args[2], 0x4000u);
    }
    return 1u;
}

static uint32_t shim_CreateThread(emu::RuntimeState& st, const uint32_t* args) {
    static uint32_t next_tid = 0x100u;
    next_tid += 4u;
    if (args && args[5]) {
        emu::wr32(st, args[5], next_tid);
    }
    return 0x5000u + next_tid;
}

static uint32_t shim_GetConsoleMode(emu::RuntimeState& st, const uint32_t* args) {
    if (args && args[1]) {
        emu::wr32(st, args[1], 0u);
    }
    return 0u;
}

static uint32_t shim_WriteFile(emu::RuntimeState& st, const uint32_t* args) {
    uint32_t to_write = args ? args[2] : 0u;
    if (args && args[3]) {
        emu::wr32(st, args[3], to_write);
    }
    return 1u;
}

static uint32_t shim_FormatMessageA(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_GetForegroundWindow(emu::RuntimeState&, const uint32_t*) {
    return 0x6000u;
}

static uint32_t shim_GetTokenInformation(emu::RuntimeState& st, const uint32_t* args) {
    // args: TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength
    uint32_t out_ptr = args ? args[2] : 0u;
    uint32_t out_len = args ? args[3] : 0u;
    uint32_t ret_len_ptr = args ? args[4] : 0u;
    if (ret_len_ptr) {
        emu::wr32(st, ret_len_ptr, 4u);
    }
    if (out_ptr && out_len >= 4u) {
        emu::wr32(st, out_ptr, 0u);
    }
    return 1u;
}

static uint32_t shim_CloseHandle(emu::RuntimeState&, const uint32_t*) {
    return 1u;
}

static uint32_t shim_DeleteCriticalSection(emu::RuntimeState&, const uint32_t*) {
    return 0u;
}

static uint32_t shim_WaitForSingleObject(emu::RuntimeState&, const uint32_t*) {
    return 0u; // WAIT_OBJECT_0
}

static uint32_t shim_GetFileType(emu::RuntimeState&, const uint32_t* args) {
    uint32_t h = args ? args[0] : 0;
    if (h == 0x10u || h == 0x11u || h == 0x12u) return 2u; // FILE_TYPE_CHAR
    return 1u; // FILE_TYPE_DISK
}

void register_default_shims(emu::RuntimeState&) {
    register_shim("KERNEL32.dll", "GetFileType", 1, shim_GetFileType);
    register_shim("KERNEL32.dll", "GetEnvironmentStrings", 0, shim_GetEnvironmentStrings);
    register_shim("KERNEL32.dll", "GetEnvironmentStringsW", 0, shim_GetEnvironmentStringsW);
    register_shim("KERNEL32.dll", "GetACP", 0, shim_GetACP);
    register_shim("KERNEL32.dll", "ExitProcess", 1, shim_ExitProcess);
    register_shim("KERNEL32.dll", "GetStdHandle", 1, shim_GetStdHandle);
    register_shim("KERNEL32.dll", "SetHandleCount", 1, shim_SetHandleCount);
    register_shim("KERNEL32.dll", "InterlockedIncrement", 1, shim_InterlockedIncrement);
    register_shim("KERNEL32.dll", "InterlockedDecrement", 1, shim_InterlockedDecrement);
    register_shim("KERNEL32.dll", "GetTickCount", 0, shim_GetTickCount);
    register_shim("KERNEL32.dll", "GetSystemTimeAsFileTime", 1, shim_GetSystemTimeAsFileTime);
    register_shim("KERNEL32.dll", "InitializeCriticalSection", 1, shim_CritSecNoop);
    register_shim("KERNEL32.dll", "EnterCriticalSection", 1, shim_CritSecNoop);
    register_shim("KERNEL32.dll", "LeaveCriticalSection", 1, shim_CritSecNoop);
    register_shim("KERNEL32.dll", "GetModuleHandleA", 1, shim_GetModuleHandleA);
    register_shim("KERNEL32.dll", "LoadLibraryA", 1, shim_LoadLibraryA);
    register_shim("KERNEL32.dll", "GetProcAddress", 2, shim_GetProcAddress);
    register_shim("KERNEL32.dll", "TlsAlloc", 0, shim_TlsAlloc);
    register_shim("KERNEL32.dll", "TlsGetValue", 1, shim_TlsGetValue);
    register_shim("KERNEL32.dll", "TlsSetValue", 2, shim_TlsSetValue);
    register_shim("KERNEL32.dll", "GetCommandLineA", 0, shim_GetCommandLineA);
    register_shim("KERNEL32.dll", "GetVersionExA", 1, shim_GetVersionExA);
    register_shim("KERNEL32.dll", "GetModuleFileNameA", 3, shim_GetModuleFileNameA);
    register_shim("KERNEL32.dll", "GetStartupInfoA", 1, shim_GetStartupInfoA);
    register_shim("KERNEL32.dll", "QueryPerformanceCounter", 1, shim_QueryPerformanceCounter);
    register_shim("KERNEL32.dll", "InterlockedExchange", 2, shim_InterlockedExchange);
    register_shim("KERNEL32.dll", "GetProcessHeap", 0, shim_GetProcessHeap);
    register_shim("KERNEL32.dll", "GetCurrentProcess", 0, shim_GetCurrentProcess);
    register_shim("KERNEL32.dll", "GetCurrentThreadId", 0, shim_GetCurrentThreadId);
    register_shim("KERNEL32.dll", "GetCurrentProcessId", 0, shim_GetCurrentProcessId);
    register_shim("KERNEL32.dll", "GetLastError", 0, shim_GetLastError);
    register_shim("KERNEL32.dll", "SetLastError", 1, shim_SetLastError);
    register_shim("KERNEL32.dll", "IsDebuggerPresent", 0, shim_IsDebuggerPresent);
    register_shim("KERNEL32.dll", "HeapCreate", 3, shim_HeapCreate);
    register_shim("KERNEL32.dll", "HeapAlloc", 3, shim_HeapAlloc);
    register_shim("KERNEL32.dll", "HeapSize", 3, shim_HeapSize);
    register_shim("KERNEL32.dll", "HeapReAlloc", 4, shim_HeapReAlloc);
    register_shim("KERNEL32.dll", "HeapFree", 4, shim_HeapFree);
    register_shim("KERNEL32.dll", "VirtualAlloc", 4, shim_VirtualAlloc);
    register_shim("KERNEL32.dll", "CreateEventA", 4, shim_CreateEventA);
    register_shim("KERNEL32.dll", "FreeEnvironmentStringsA", 1, shim_FreeEnvironmentStringsA);
    register_shim("KERNEL32.dll", "SetUnhandledExceptionFilter", 1, shim_SetUnhandledExceptionFilter);
    register_shim("KERNEL32.dll", "GetSystemInfo", 1, shim_GetSystemInfo);
    register_shim("KERNEL32.dll", "CreateMutexA", 3, shim_CreateMutexA);
    register_shim("KERNEL32.dll", "IsBadReadPtr", 2, shim_IsBadReadPtr);
    register_shim("ADVAPI32.dll", "RegOpenKeyExA", 5, shim_RegOpenKeyExA);
    register_shim("ADVAPI32.dll", "RegQueryValueExA", 6, shim_RegQueryValueExA);
    register_shim("ADVAPI32.dll", "RegCloseKey", 1, shim_RegCloseKey);
    register_shim("ADVAPI32.dll", "AllocateAndInitializeSid", 11, shim_AllocateAndInitializeSid);
    register_shim("ADVAPI32.dll", "OpenProcessToken", 3, shim_OpenProcessToken);
    register_shim("KERNEL32.dll", "CreateThread", 6, shim_CreateThread);
    register_shim("KERNEL32.dll", "GetConsoleMode", 2, shim_GetConsoleMode);
    register_shim("KERNEL32.dll", "WriteFile", 5, shim_WriteFile);
    register_shim("KERNEL32.dll", "FormatMessageA", 7, shim_FormatMessageA);
    register_shim("USER32.dll", "GetForegroundWindow", 0, shim_GetForegroundWindow);
    register_shim("ADVAPI32.dll", "GetTokenInformation", 5, shim_GetTokenInformation);
    register_shim("KERNEL32.dll", "CloseHandle", 1, shim_CloseHandle);
    register_shim("KERNEL32.dll", "DeleteCriticalSection", 1, shim_DeleteCriticalSection);
    register_shim("KERNEL32.dll", "WaitForSingleObject", 2, shim_WaitForSingleObject);
}

} // namespace shims
