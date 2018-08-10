#pragma once

#include <Windows.h>
#include "hModules.h"
#include "..\\HoShiMin's API\\HookHelper.h"

typedef NTSTATUS(NTAPI *_NtContinue)(PCONTEXT Context, BOOL TestAlert);
typedef NTSTATUS(NTAPI *_NtSetContextThread)(HANDLE ThreadHandle, PCONTEXT Context);

typedef NTSTATUS(NTAPI *_NtContinueCallback)(
    OUT PBOOL SkipOriginalCall,
    PCONTEXT Context,
    BOOL TestAlert
);

typedef NTSTATUS(NTAPI *_PreNtSetContextThread)(
    OUT PBOOL SkipOriginalCall,
    HANDLE ThreadHandle,
    PCONTEXT Context
);

typedef NTSTATUS(NTAPI *_PostNtSetContextThread)(
    IN NTSTATUS ReturnValue,
    HANDLE ThreadHandle,
    PCONTEXT Context
);

class ContextFilter final {
private:
    static BOOL Initialized, Enabled;
    static BOOL Initialize();
    static HOOK_INFO HookInfo[2];
    static _NtContinue NtContinue, OrgnlNtContinue;
    static _NtSetContextThread NtSetContextThread, OrgnlNtSetContextThread;
    static _NtContinueCallback NtContinueCallback;
    static _PreNtSetContextThread PreSetContext;
    static _PostNtSetContextThread PostSetContext;
    static NTSTATUS NTAPI HkdNtContinue(PCONTEXT Context, BOOL TestAlert);
    static NTSTATUS NTAPI HkdNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
public:
    static VOID SetupContextCallbacks(
        OPTIONAL _NtContinueCallback PreNtContinue = NULL, 
        OPTIONAL _PreNtSetContextThread PreNtSetContextThread = NULL,
        OPTIONAL _PostNtSetContextThread PostNtSetContextThread = NULL
    );
    static BOOL EnableContextFilter();
    static VOID DisableContextFilter();
};