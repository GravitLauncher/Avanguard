#include "stdafx.h"
#include "AvnDefinitions.h"
#include "JavaBindings.h"
#include "ThreatTypes.h"
#include "hModules.h"
#include "ThreatElimination.h"

static _AvnThreatNotifier _ThreatCallback = NULL;

typedef NTSTATUS (NTAPI *_NtContinue)(PCONTEXT Context, BOOL TestAlert);
static const _NtContinue NtContinue = (_NtContinue)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtContinue"));

[[noreturn]]
VOID TerminateInternal() {
    __fastfail(0);
    CONTEXT Context; // Stay uninitialized
    NtContinue(&Context, FALSE);
}

VOID EliminateThreat(AVN_THREAT Threat, OPTIONAL PVOID Data, AVN_ET_ACTION Action) 
{
    if (_ThreatCallback)
        if (_ThreatCallback(Threat, Data)) return;
#ifdef JAVA_BINDINGS
    if (CallJavaNotifier(Threat) == etContinue) return;
#endif

    if (Action != etTerminate) return;

    CONTEXT Context = { 0 };
    RtlCaptureContext(&Context);
#ifdef _AMD64_
    Context.Rip = (SIZE_T)TerminateInternal;
#else
    Context.Eip = (SIZE_T)TerminateInternal;
#endif
    NtContinue(&Context, FALSE);
}

VOID SetupNotificationRoutine(_AvnThreatNotifier ThreatCallback) {
    _ThreatCallback = ThreatCallback;
}