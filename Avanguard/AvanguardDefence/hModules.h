#pragma once

#include <Windows.h>

typedef PVOID (WINAPI *_GetProcAddress)(HMODULE hModule, LPCSTR ProcName);

class hModules final {
private:
    static BOOL Initialized;
    static HMODULE _hNtdll;
    static HMODULE _hKernelBase;
    static HMODULE _hKernel32;
    static HMODULE _hProcess;
    static _GetProcAddress _XoredQueryAddress;
public:
    static HMODULE _hCurrent; // Current module
    static inline HMODULE hNtdll();
    static inline HMODULE hKernelBase();
    static inline HMODULE hKernel32();
    static inline HMODULE hProcess();
    static inline HMODULE hCurrent();
    static inline PVOID WINAPI QueryAddress(HMODULE hModule, LPCSTR ProcName);
};



#define GET_HMODULE(VarName, LibName) VarName ? VarName : VarName = GetModuleHandle(LibName)

inline HMODULE hModules::hNtdll() {
    return GET_HMODULE(_hNtdll, L"ntdll.dll");
}

inline HMODULE hModules::hKernelBase() {
    return GET_HMODULE(_hKernelBase, L"kernelbase.dll");
}

inline HMODULE hModules::hKernel32() {
    return GET_HMODULE(_hKernel32, L"kernel32.dll");
}

inline HMODULE hModules::hProcess() {
    return GET_HMODULE(_hProcess, NULL);
}

inline HMODULE hModules::hCurrent() {
    return _hCurrent;
}

inline PVOID WINAPI hModules::QueryAddress(HMODULE hModule, LPCSTR ProcName) {
    return GetProcAddress(hModule, ProcName);
    const SIZE_T Key = (SIZE_T)0xF3C2A713B4340C2A;
    if (!_XoredQueryAddress)
        _XoredQueryAddress = (_GetProcAddress)((SIZE_T)GetProcAddress(hKernel32(), "GetProcAddress") ^ Key);
    return ((_GetProcAddress)((SIZE_T)_XoredQueryAddress ^ Key))(hModule, ProcName);
}

#undef GET_HMODULE