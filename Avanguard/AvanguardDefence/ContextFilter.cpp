#include "stdafx.h"
#include "ContextFilter.h"

BOOL ContextFilter::Initialized = FALSE;
BOOL ContextFilter::Enabled = FALSE;
HOOK_INFO ContextFilter::HookInfo[2] = { 0 };
_NtContinue ContextFilter::NtContinue = NULL;
_NtContinue ContextFilter::OrgnlNtContinue = NULL;
_NtSetContextThread ContextFilter::NtSetContextThread = NULL;
_NtSetContextThread ContextFilter::OrgnlNtSetContextThread = NULL;
_NtContinueCallback ContextFilter::NtContinueCallback = NULL;
_PreNtSetContextThread ContextFilter::PreSetContext = NULL;
_PostNtSetContextThread ContextFilter::PostSetContext = NULL;

BOOL ContextFilter::Initialize() {
    if (Initialized) return TRUE;
    NtContinue = (_NtContinue)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtContinue"));
    NtSetContextThread = (_NtSetContextThread)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtSetContextThread"));

    HookInfo[0] = INTERCEPTION_ENTRY(NtContinue, NtContinue);
    HookInfo[1] = INTERCEPTION_ENTRY(NtSetContextThread, NtSetContextThread);

    return Initialized = NtContinue && NtSetContextThread;
}

NTSTATUS NTAPI ContextFilter::HkdNtContinue(PCONTEXT Context, BOOL TestAlert) {
    PRE_FILTRATE_TO(
        NTSTATUS, Status, NtContinue, NtContinueCallback,
        Context, TestAlert
    );
    return Status;
}

NTSTATUS NTAPI ContextFilter::HkdNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    FILTRATE_TO(
        NTSTATUS, Status, NtSetContextThread, PreSetContext, PostSetContext,
        ThreadHandle, Context
    );
    return Status;
}

BOOL ContextFilter::EnableContextFilter() {
    if (!Initialized && !Initialize()) return FALSE;
    if (Enabled) return TRUE;

    MH_Initialize();
    return Enabled = HookEmAll(HookInfo, sizeof(HookInfo) / sizeof(HookInfo[0]));
}

VOID ContextFilter::DisableContextFilter() {
    if (!Initialized && !Initialize()) return;
    if (!Enabled) return;
    UnHookEmAll(HookInfo, sizeof(HookInfo) / sizeof(HookInfo[0]));
    Enabled = FALSE;
}

VOID ContextFilter::SetupContextCallbacks(
    OPTIONAL _NtContinueCallback PreNtContinue,
    OPTIONAL _PreNtSetContextThread PreNtSetContextThread,
    OPTIONAL _PostNtSetContextThread PostNtSetContextThread
) {
    NtContinueCallback = PreNtContinue;
    PreSetContext = PreNtSetContextThread;
    PostSetContext = PostNtSetContextThread;
}


