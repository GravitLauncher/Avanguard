#include "stdafx.h"
#include "AppInitDlls.h"

BOOL AppInitDlls::Enabled = FALSE;
BOOL AppInitDlls::Initialized = FALSE;
HOOK_INFO AppInitDlls::HookInfo;

INTERCEPTION(VOID, WINAPI, LoadAppInitDlls) {
    return;
}

BOOL AppInitDlls::Initialize() {
    if (Initialized) return TRUE;
    HookInfo = INTERCEPTION_ENTRY(
        hModules::QueryAddress(hModules::hKernel32(), XORSTR("LoadAppInitDlls")),
        LoadAppInitDlls
    );
    return Initialized = HookInfo.TargetProc != NULL;
}

BOOL AppInitDlls::DisableAppInitDlls() {
    if (!Initialized && !Initialize()) return FALSE;
    if (Enabled) return TRUE;
    MH_Initialize();
    return Enabled = HookEmAll(&HookInfo, 1);
}

VOID AppInitDlls::EnableAppInitDlls() {
    if (!Initialized && !Initialize()) return;
    if (Enabled) {
        UnHookEmAll(&HookInfo, 1);
        Enabled = FALSE;
    }
}