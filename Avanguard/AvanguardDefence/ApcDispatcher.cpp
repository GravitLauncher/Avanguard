#include "stdafx.h"
#include "ApcDispatcher.h"

typedef NTSTATUS(NTAPI *_NtContinue)(
    IN PCONTEXT	ThreadContext,
    IN BOOLEAN	RaiseAlert
);

const _NtContinue NtContinue = (_NtContinue)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtContinue"));
const _NtTestAlert NtTestAlert = (_NtTestAlert)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtTestAlert"));

static PVOID pKiUserApcDispatcher;
static _ApcCallback ApcCallback = NULL;

#ifdef _AMD64_
extern "C" void KiUserApcHandler();
extern "C" PVOID OrgnlKiUserApcDispatcher;

PVOID OrgnlKiUserApcDispatcher;

extern "C"
BOOL NTAPI ApcHandler(PCONTEXT Context) {
    PVOID ApcProc = (PVOID)Context->P1Home;
    PVOID ReturnAddress = (PVOID)Context->Rip;
    if (ApcCallback) 
        if (ApcCallback(ApcProc, ReturnAddress))
            return TRUE;
    return NT_SUCCESS(NtContinue(Context, FALSE));
}
#else 
typedef VOID (NTAPI *_KiUserApcDispatcher)(
    PVOID NormalRoutine, 
    PVOID SystemArgument1, 
    PVOID SystemArgument2, 
    CONTEXT Context
);

_KiUserApcDispatcher OrgnlKiUserApcDispatcher;

__declspec(naked)
VOID NTAPI HkdKiUserApcDispatcher(
    PVOID NormalRoutine,	// ApcProc
    PVOID SystemArgument1,	// Argument
    PVOID SystemArgument2,
    CONTEXT Context
) {
    __asm {
// Выравниваем базу аргументов:
        push ebp
        mov ebp, esp
        
// Вызываем каллбэк:
        mov eax, ApcCallback
        test eax, eax
        jz Continue
        mov ecx, Context.Eip
        mov eax, NormalRoutine
        push ecx
        push eax
        call ApcCallback
        test eax, eax
        jz Continue // Возвращаемся без вызова APC
        
// Возвращаем стек в исходное состояние:
        mov esp, ebp
        pop ebp

// Уходим на KiUserApcDispatcher:
        jmp OrgnlKiUserApcDispatcher
        ret // Если что-то пойдёт не так

Continue:
        lea ecx, Context // Запоминаем адрес Context
        
// Возвращаем стек в исходное состояние:
        mov esp, ebp
        pop ebp

        push FALSE
        push ecx
        call NtContinue // Отсюда мы уже не вернёмся
        ret // А вдруг?
    }
}
#endif

BOOL ApcDispatcher::Initialized = FALSE;

BOOL ApcDispatcher::EnableApcFilter() {
    if (Initialized) return TRUE;
    
    MH_Initialize();
    pKiUserApcDispatcher = hModules::QueryAddress(hModules::hNtdll(), XORSTR("KiUserApcDispatcher"));
#ifdef _AMD64_
    MH_STATUS MhStatus = MH_CreateHook(pKiUserApcDispatcher, &KiUserApcHandler, (LPVOID*)&OrgnlKiUserApcDispatcher);
#else
    MH_STATUS MhStatus = MH_CreateHook(pKiUserApcDispatcher, HkdKiUserApcDispatcher, (LPVOID*)&OrgnlKiUserApcDispatcher);
#endif
    if (MhStatus == MH_OK) MhStatus = MH_EnableHook(pKiUserApcDispatcher);
    if (MhStatus != MH_OK) MH_RemoveHook(pKiUserApcDispatcher);

    return Initialized = MhStatus == MH_OK;
}

VOID ApcDispatcher::DisableApcFilter() {
    if (!Initialized) return;
    MH_DisableHook(pKiUserApcDispatcher);
    MH_RemoveHook(pKiUserApcDispatcher);
    ApcDispatcher::Initialized = FALSE;
}

VOID ApcDispatcher::SetupApcCallback(_ApcCallback Callback) {
    ApcCallback = Callback;
}