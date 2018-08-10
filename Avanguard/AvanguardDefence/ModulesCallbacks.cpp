#include "stdafx.h"
#include "ModulesCallbacks.h"

#include "AvnApi.h"
extern AVN_API AvnApi;

ModulesStorage ValidModulesStorage(TRUE);

static _OnWindowsHookLoad WinHookLoadCallback;
static _OnUnknownTraceLoad UnknownTraceLoadCallback;

NTSTATUS CALLBACK PreLoadModuleCallback(
    OUT PBOOL			SkipOriginalCall,
    IN PWCHAR			PathToFile,
    IN PULONG			Flags,
    IN PUNICODE_STRING	ModuleFileName,
    OUT PHANDLE			ModuleHandle
) {
#if defined WINDOWS_HOOKS_FILTER || defined STACKTRACE_CHECK
    AvnApi.AvnLock();

#ifdef WINDOWS_HOOKS_FILTER
    if (WinHooks::IsCalledFromWinHook() && WinHookLoadCallback) 
        *SkipOriginalCall = !WinHookLoadCallback(ModuleFileName);
#endif

    if (!*SkipOriginalCall) {
#ifdef STACKTRACE_CHECK
        const int TraceCount = 35;
        PVOID Ptrs[TraceCount];
        USHORT Captured = CaptureStackBackTrace(0, TraceCount, Ptrs, NULL);
        for (unsigned short i = 0; i < Captured; i++) {
            PVOID Address = Ptrs[i];
            HMODULE hModule = GetModuleBase(Address);
#ifdef MEMORY_FILTER
            BOOL IsAddressAllowed = hModule == NULL 
                ? VMStorage.IsMemoryInMap(Address) 
                : ValidModulesStorage.IsModuleInStorage(hModule);
#else
            BOOL IsAddressAllowed = hModule != NULL 
                ? ValidModulesStorage.IsModuleInStorage(hModule) 
                : FALSE;
#endif
            if (!IsAddressAllowed && *SkipOriginalCall && UnknownTraceLoadCallback) 
                *SkipOriginalCall = !UnknownTraceLoadCallback(Address, ModuleFileName);
        }
#endif
    }

    AvnApi.AvnUnlock();
#endif
    
    return STATUS_SUCCESS;
}

VOID CALLBACK DllNotificationRoutine(
    LDR_NOTIFICATION_REASON Reason,
    IN PLDR_DLL_NOTIFICATION_DATA NotificationData,
    IN PCONTEXT Context
) {
    switch (Reason) {
    case LdrModuleLoaded:
        ValidModulesStorage.AddModule((HMODULE)NotificationData->DllBase);
        break;

    case LdrModuleUnloaded:
        ValidModulesStorage.RemoveModule((HMODULE)NotificationData->DllBase);
        break;
    }
}

VOID SetupWindowsHooksFilter(_OnWindowsHookLoad Callback) {
    WinHookLoadCallback = Callback;
}

VOID SetupUnknownTraceLoadCallback(_OnUnknownTraceLoad Callback) {
    UnknownTraceLoadCallback = Callback;
}