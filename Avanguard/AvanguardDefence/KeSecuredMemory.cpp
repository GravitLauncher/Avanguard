#include "stdafx.h"
#include "KeSecuredMemory.h"

typedef BOOL (WINAPI *_AddSecureMemoryCacheCallback)(
    PSECURE_MEMORY_CACHE_CALLBACK Callback
);

typedef BOOL (WINAPI *_RemoveSecureMemoryCacheCallback)(
    PSECURE_MEMORY_CACHE_CALLBACK Callback
);

_KeSecuredMemoryCallback MmCallback = NULL;
BOOL MmCallbackIsActive = FALSE;

BOOLEAN CALLBACK SecureMemoryCacheCallback(
    _In_ PVOID  Addr,
    _In_ SIZE_T Range
) {
    return MmCallback ? MmCallback(Addr, Range) : TRUE;
}

BOOL SetupSecuredMemoryCallback(_KeSecuredMemoryCallback Callback) {
    static _AddSecureMemoryCacheCallback UAddSecureMemoryCacheCallback = NULL;
    if (UAddSecureMemoryCacheCallback) {
        UAddSecureMemoryCacheCallback = (_AddSecureMemoryCacheCallback)
            GetProcAddress(GetModuleHandle(L"kernel32.dll"), "AddSecureMemoryCacheCallback");
        if (UAddSecureMemoryCacheCallback == NULL) return FALSE;
    }

    if (Callback == NULL) {
        if (MmCallbackIsActive)
            return RemoveSecuredMemoryCallback();
        return FALSE;
    }
    
    MmCallback = Callback;
    if (!MmCallbackIsActive)
        return MmCallbackIsActive = UAddSecureMemoryCacheCallback(SecureMemoryCacheCallback);
    return TRUE;
}

BOOL RemoveSecuredMemoryCallback() {
    static _RemoveSecureMemoryCacheCallback URemoveSecureMemoryCacheCallback = NULL;
    if (URemoveSecureMemoryCacheCallback) {
        URemoveSecureMemoryCacheCallback = (_RemoveSecureMemoryCacheCallback)
            GetProcAddress(GetModuleHandle(L"kernel32.dll"), "RemoveSecureMemoryCacheCallback");
        if (URemoveSecureMemoryCacheCallback == NULL) return FALSE;
    }
    return MmCallbackIsActive = !URemoveSecureMemoryCacheCallback(SecureMemoryCacheCallback);
}