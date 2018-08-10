#include "stdafx.h"
#include "TLS.h"

int TlsMain();

// Получаем фактическую точку входа:
PVOID GetEntryPoint(HMODULE hModule) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + DosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeaders->OptionalHeader;
    return (PBYTE)hModule + OptionalHeader->AddressOfEntryPoint;
}

// Получаем HMODULE текущего модуля:
HMODULE GetCurrentModule() {
    HMODULE hModule = NULL;
    GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCTSTR)GetCurrentModule,
        &hModule
    );
    return hModule;
}

// hModule текущего модуля:
static HMODULE hInstance = GetCurrentModule();

VOID WINAPI TlsCallback(HMODULE hModule, DWORD Reason, PCONTEXT Context) {
    if (hInstance == NULL) hInstance = GetCurrentModule();
    if (hModule != hInstance || Reason != DLL_PROCESS_ATTACH) return;

    static BOOL IsCrtInitialized = FALSE;

    if (!IsCrtInitialized) { // Сюда мы ещё вернёмся
        IsCrtInitialized = TRUE;
        _EntryPoint EntryPoint = (_EntryPoint)GetEntryPoint(hInstance);
        if (EntryPoint) EntryPoint();
        return;
    }

    // Не позволим выйти из каллбэка:
    int Status;
    __try {
        Status = TlsMain();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = 0xFFFFFFFF;
    }

    // ExitProcess(Status);
}

int TlsMain() {
    return 0;
}