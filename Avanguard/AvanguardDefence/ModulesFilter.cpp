#include "stdafx.h"
#include "ModulesFilter.h"

BOOL				ModulesFilter::Enabled		= FALSE;
BOOL				ModulesFilter::Initialized	= FALSE;
HOOK_INFO			ModulesFilter::HookInfo[2]	= { 0 };
PVOID				ModulesFilter::Cookie = NULL;

_LdrLoadDll			ModulesFilter::LdrLoadDll	= NULL;
_LdrUnloadDll		ModulesFilter::LdrUnloadDll	= NULL;
_LdrLoadDll			ModulesFilter::OrgnlLdrLoadDll	 = NULL;
_LdrUnloadDll		ModulesFilter::OrgnlLdrUnloadDll = NULL;

_PreLoadCallback	ModulesFilter::PreLoadCallback		= NULL;
_PostLoadCallback	ModulesFilter::PostLoadCallback		= NULL;
_PreUnloadCallback	ModulesFilter::PreUnloadCallback	= NULL;
_PostUnloadCallback	ModulesFilter::PostUnloadCallback	= NULL;

_LdrRegisterDllNotification		ModulesFilter::LdrRegisterDllNotification	= NULL;
_LdrUnregisterDllNotification	ModulesFilter::LdrUnregisterDllNotification = NULL;
_DllNotificationRoutine			ModulesFilter::DllNotificationRoutine		= NULL;

BOOL ModulesFilter::Initialize() {
    if (Initialized) return TRUE;

    LdrRegisterDllNotification =
        (_LdrRegisterDllNotification)hModules::QueryAddress(hModules::hNtdll(), XORSTR("LdrRegisterDllNotification"));
    LdrUnregisterDllNotification =
        (_LdrUnregisterDllNotification)hModules::QueryAddress(hModules::hNtdll(), XORSTR("LdrUnregisterDllNotification"));
    
    LdrLoadDll = (_LdrLoadDll)hModules::QueryAddress(hModules::hNtdll(), XORSTR("LdrLoadDll"));
    LdrUnloadDll = (_LdrUnloadDll)hModules::QueryAddress(hModules::hNtdll(), XORSTR("LdrUnloadDll"));

    HookInfo[0] = INTERCEPTION_ENTRY(LdrLoadDll, LdrLoadDll);
    HookInfo[1] = INTERCEPTION_ENTRY(LdrUnloadDll, LdrUnloadDll);

    return Initialized = LdrLoadDll && LdrUnloadDll;
}



NTSTATUS ModulesFilter::HkdLdrLoadDll(
    IN PWCHAR			PathToFile,
    IN PULONG			Flags,
    IN PUNICODE_STRING	ModuleFileName,
    OUT PHANDLE			ModuleHandle
) {
    FILTRATE_TO(
        NTSTATUS, Status, LdrLoadDll, PreLoadCallback, PostLoadCallback,
        PathToFile, Flags, ModuleFileName, ModuleHandle	
    );
    return Status;
}

NTSTATUS ModulesFilter::HkdLdrUnloadDll(
    IN HANDLE ModuleHandle
) {
    FILTRATE_TO(
        NTSTATUS, Status, LdrUnloadDll, PreUnloadCallback, PostUnloadCallback,
        ModuleHandle
    );
    return Status;
}



VOID CALLBACK ModulesFilter::LdrDllNotificationFunction(
    _In_		ULONG						NotificationReason,
    _In_		PLDR_DLL_NOTIFICATION_DATA	NotificationData,
    _In_opt_	PVOID						Context
) {
    if (DllNotificationRoutine)
        DllNotificationRoutine((LDR_NOTIFICATION_REASON)NotificationReason, NotificationData, (PCONTEXT)Context);
}



BOOL ModulesFilter::EnableModulesFilter() {
    if (!Initialized && !Initialize()) return FALSE;
    if (Enabled) return TRUE;

    MH_Initialize();
    return Enabled = HookEmAll(HookInfo, sizeof(HookInfo) / sizeof(HookInfo[0]));
}

VOID ModulesFilter::DisableModulesFilter() {
    if (!Initialized && !Initialize()) return;
    if (!Enabled) return;
    UnHookEmAll(HookInfo, sizeof(HookInfo) / sizeof(HookInfo[0]));
    Enabled = FALSE;
}

BOOL ModulesFilter::EnableDllNotification() {
    if (!Initialized && !Initialize()) return FALSE;
    if (Cookie) return TRUE;

    if (LdrRegisterDllNotification)
        return LdrRegisterDllNotification(
            0,
            LdrDllNotificationFunction,
            NULL,
            &Cookie
        ) == STATUS_SUCCESS;
    return FALSE;
}

VOID ModulesFilter::DisableDllNotification() {
    if (!Initialized && !Initialize()) return;
    if (Cookie == NULL) return;

    if (LdrUnregisterDllNotification)
        LdrUnregisterDllNotification(Cookie);
}

VOID ModulesFilter::SetupFilterCallbacks(
    OPTIONAL _PreLoadCallback PreLoad,
    OPTIONAL _PostLoadCallback PostLoad,
    OPTIONAL _PreUnloadCallback PreUnload,
    OPTIONAL _PostUnloadCallback PostUnload
) {
    PreLoadCallback = PreLoad;
    PostLoadCallback = PostLoad;
    PreUnloadCallback = PreUnload;
    PostUnloadCallback = PostUnload;
}

VOID ModulesFilter::SetupNotificationCallbacks(
    OPTIONAL _DllNotificationRoutine Callback
) {
    DllNotificationRoutine = Callback;
}