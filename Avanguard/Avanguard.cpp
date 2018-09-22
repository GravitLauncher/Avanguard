#include "stdafx.h"

#include <functional>
#include <clocale>

#include "AvnDefinitions.h"
#include "AntiMacros.h"
#include "ThreadsFilter.h"
#include "ModulesFilter.h"
#include "PEAnalyzer.h"
#include "ModulesCallbacks.h"
#include "ModulesStorage.h"
#include "MemoryCallbacks.h"
#include "CheckHook.h"
#include "ProcessAPI.h"
#include "PebTeb.h"
#include "Mitigations.h"
#include "AppInitDlls.h"
#include "WinTrusted.h"
#include "ApcDispatcher.h"
#include "DACL.h"
#include "ModulesUtils.h"
#include "ContextFilter.h"
#include "HWIDsUtils.h"
#include "ThreatElimination.h"
#include "Remapping.h"
#include "HandlesKeeper.h"

#include "SfcWrapper.h"

#include "HoShiMin's API\\StringsAPI.h"
#include "HoShiMin's API\\DisasmHelper.h"
#include "HoShiMin's API\\JitHelper.h"

#include <intrin.h>

#ifdef SELF_REMAPPING
// Be ready for self-remapping code:
#pragma comment(linker, "/ALIGN:65536")
#endif

#include "AvnApi.h"
extern AVN_API AvnApi;
extern VOID AvnInitializeApi();
extern "C" __declspec(dllexport) const PAVN_API Stub = &AvnApi;

BOOL IsAvnStarted = FALSE;
BOOL IsAvnStaticLoaded = FALSE;

#ifdef DEBUG_OUTPUT
static HANDLE hLog = CreateFile(XORSTR(L"AvnLog.log"), FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

void Log(const std::wstring& Text) {
    if (hLog == INVALID_HANDLE_VALUE) return;

    static BOOL Initialized = FALSE;
    static CRITICAL_SECTION CriticalSection;
    if (!Initialized) {
        InitializeCriticalSectionAndSpinCount(&CriticalSection, 0xC0000000);
        Initialized = TRUE;
    }

    int size = sizeof(std::wstring::value_type);
    std::wstring ToWrite = XORSTR(L"[PID: ") + ValToWideStr(GetCurrentProcessId()) + XORSTR(L"] ") + Text + L"\r\n";

    EnterCriticalSection(&CriticalSection);
    DWORD BytesWritten;
    WriteFile(hLog, ToWrite.c_str(), (DWORD)ToWrite.length() * sizeof(std::wstring::value_type), &BytesWritten, NULL);
    FlushFileBuffers(hLog);
    LeaveCriticalSection(&CriticalSection);
}

VOID DisassembleAndLog(PVOID Address, BYTE InstructionsCount) {
    disassemble([](void* Code, void* Address, unsigned int InstructionLength, char* Disassembly) -> bool {
        std::wstring Bytes;
        for (unsigned int i = 0; i < InstructionLength; i++) {
            Bytes += ValToWideHex(*((PBYTE)Code + i), 2, FALSE);
            if (i != InstructionLength - 1) Bytes += L" ";
        }
        Bytes = FillRightWide(Bytes, 22, L' ');
        Log(L"\t\t" + ValToWideHex(Address, 16) + L"\t" + Bytes + L"\t" + AnsiToWide(Disassembly));
        return true;
    }, Address, Address, InstructionsCount);
}
#else
#define Log(Argument) UNREFERENCED_PARAMETER(Argument)
#define DisassembleAndLog(Address, InstructionsCount)
#endif

#ifdef SELF_REMAPPING
VOID RemapAvnExecutableSections() {
    const BOOL Status = RemapModule(hModules::hCurrent(), TRUE);
    Log(Status ? XORSTR(L"[v] Module successfully remapped") : XORSTR(L"[x] Unable to remap module!"));
}
#endif

#ifdef TIMERED_CHECKINGS
typedef NTSTATUS(NTAPI *_RtlCreateTimerQueue)(
    _Out_ PHANDLE TimerQueueHandle
    );

typedef NTSTATUS(NTAPI *_RtlDeleteTimerQueue)(
    _In_ HANDLE TimerQueueHandle
    );

typedef NTSTATUS(NTAPI *_RtlCreateTimer)(
    _In_ HANDLE 	TimerQueueHandle,
    _Out_ PHANDLE 	Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_ PVOID 	Context,
    _In_ DWORD 	DueTime,
    _In_ DWORD 	Period,
    _In_ ULONG 	Flags
    );


typedef NTSTATUS(NTAPI *_RtlDeleteTimer)(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerHandle,
    _In_ HANDLE CompletionEvent
    );

const _RtlCreateTimerQueue RtlCreateTimerQueue = (_RtlCreateTimerQueue)hModules::QueryAddress(hModules::hNtdll(), "RtlCreateTimerQueue");
const _RtlDeleteTimerQueue RtlDeleteTimerQueue = (_RtlDeleteTimerQueue)hModules::QueryAddress(hModules::hNtdll(), "RtlDeleteTimerQueue");
const _RtlCreateTimer RtlCreateTimer = (_RtlCreateTimer)hModules::QueryAddress(hModules::hNtdll(), "RtlCreateTimer");
const _RtlDeleteTimer RtlDeleteTimer = (_RtlDeleteTimer)hModules::QueryAddress(hModules::hNtdll(), "RtlDeleteTimer");
#endif

#ifdef THREADS_FILTER
static PVOID RestrictedAddresses[] = {
    hModules::QueryAddress(hModules::hNtdll(), XORSTR("LdrLoadDll")),
    hModules::QueryAddress(hModules::hKernel32(), XORSTR("LoadLibraryA")),
    hModules::QueryAddress(hModules::hKernel32(), XORSTR("LoadLibraryW")),
    hModules::QueryAddress(hModules::hKernel32(), XORSTR("LoadLibraryExA")),
    hModules::QueryAddress(hModules::hKernel32(), XORSTR("LoadLibraryExW")),
    hModules::QueryAddress(hModules::hKernelBase(), XORSTR("LoadLibraryA")),
    hModules::QueryAddress(hModules::hKernelBase(), XORSTR("LoadLibraryW")),
    hModules::QueryAddress(hModules::hKernelBase(), XORSTR("LoadLibraryExA")),
    hModules::QueryAddress(hModules::hKernelBase(), XORSTR("LoadLibraryExW"))
};

BOOL IsThreadAllowed(PVOID EntryPoint) {
    HMODULE hModule = GetModuleBase(EntryPoint);

    if (hModule != NULL) {
        if (hModule == hModules::hNtdll() ||
            hModule == hModules::hKernel32() ||
            hModule == hModules::hKernelBase()
            ) {
            for (PVOID Address : RestrictedAddresses)
                if (Address == EntryPoint) return FALSE;
        }
#ifdef MODULES_FILTER
        return ValidModulesStorage.IsModuleInStorage(hModule);
#else
        return TRUE;
#endif
    }
#ifdef MEMORY_FILTER
    else {
        return VMStorage.IsMemoryInMap(EntryPoint);
    }
#else
    return TRUE;
#endif
}

BOOL CALLBACK OnThreadCreated(
    PCONTEXT Context,
    BOOL ThreadIsLocal
) {
#ifdef _AMD64_
    PVOID EntryPoint = (PVOID)Context->Rcx;
#else
    PVOID EntryPoint = (PVOID)Context->Eax;
#endif

    if (!ThreadIsLocal && !(ThreadIsLocal = IsThreadAllowed(EntryPoint))) {
        Log(XORSTR(L"[x] Thread ") + ValToWideStr(GetCurrentThreadId()) + XORSTR(L" is blocked!"));
        EliminateThreat(avnRemoteThread, NULL, etContinue);
    }

#ifdef MITIGATIONS
    Mitigations::SetThreadAllowedDynamicCode();
#endif
    return ThreadIsLocal;
}
#endif

#ifdef WINDOWS_HOOKS_FILTER
BOOL CALLBACK OnWindowsHookLoadLibrary(PUNICODE_STRING ModuleFileName) {
    static std::unordered_set<UINT64> BlockedLibs;

    std::wstring Path(ModuleFileName->Buffer);
    std::wstring Name(LowerCase(ExtractFileName(Path)));

    UINT64 NameHash = t1ha(Name.c_str(), Name.length() * sizeof(std::wstring::value_type), 0x1EE7C0DEC0FFEE);
    if (BlockedLibs.find(NameHash) != BlockedLibs.end()) return FALSE;

    Log(XORSTR(L"[!] Attempt to load ") + Path + XORSTR(L" through the windows hooks!"));

    DWORD LastError = GetLastError();
    BOOL IsFileAllowed = Sfc::IsFileProtected(ModuleFileName->Buffer);
    Log(IsFileAllowed ? (XORSTR(L"[v] Module ") + Path + XORSTR(L" allowed!")) : (XORSTR(L"[!] Module ") + Path + XORSTR(L" not a system module!")));
    if (IsFileAllowed) return TRUE;

    if (!IsFileAllowed) {
        Log(XORSTR(L"[i] Checking the sign of ") + Path);
        IsFileAllowed = IsFileSigned(ModuleFileName->Buffer, FALSE);
    }

    if (!IsFileAllowed) {
        Log(XORSTR(L"[i] Checking the path of ") + Path);
        LowerCaseRef(Path);
        IsFileAllowed = true;
    }

    if (!IsFileAllowed) BlockedLibs.emplace(NameHash);

    Log(IsFileAllowed ? (XORSTR(L"[v] Module ") + Path + XORSTR(L" allowed!")) : (XORSTR(L"[x] Module ") + Path + XORSTR(L" is blocked!")));

    if (!IsFileAllowed) EliminateThreat(avnWindowsHooksInjection, NULL, etContinue);
    return IsFileAllowed;
}
#endif

#ifdef STACKTRACE_CHECK
BOOL CALLBACK OnUnknownTraceLoadLibrary(PVOID Address, PUNICODE_STRING ModuleFileName) {
    Log(XORSTR(L"[x] Unknown trace entry ") + ValToWideHex(Address, 16) + XORSTR(L" on load module ") + std::wstring(ModuleFileName->Buffer));
    EliminateThreat(avnUnknownTraceLoadLibrary, NULL, etTerminate);
    return FALSE;
}
#endif

#ifdef CONTEXT_FILTER
BOOL IsTraceValid() {
    const ULONG TraceSize = 30;
    PVOID Trace[TraceSize];
    ULONG Captured = CaptureStackBackTrace(0, TraceSize, Trace, NULL);
    for (unsigned int i = 0; i < Captured; i++) {
        HMODULE hModule = GetModuleBase(Trace[i]);
        if (hModule != NULL) {
            if (!ValidModulesStorage.IsModuleInStorage(hModule)) {
                Log(XORSTR(L"[x] Context manipulation from unknown module ") + GetModuleName(hModule));
                return FALSE;
            }
        }
        else {
            if (!VMStorage.IsMemoryInMap(Trace[i])) {
                Log(XORSTR(L"[x] Context manipulation from unknown memory ") + ValToWideHex(Trace[i], 16));
                return FALSE;
            }
        }
    }
    return TRUE;
}

NTSTATUS NTAPI PreNtContinue(IN PBOOL SkipOriginalCall, PCONTEXT Context, BOOL TestAlert) {
    if (!IsTraceValid()) {
        Log(XORSTR(L"[x] PreNtContinue detected unknown trace element!"));
        EliminateThreat(avnContextManipulation, NULL, etTerminate);
        *SkipOriginalCall = TRUE;
        return STATUS_ACCESS_DENIED;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI PreSetContext(IN PBOOL SkipOriginalCall, HANDLE ThreadHandle, PCONTEXT Context) {
    if (!IsTraceValid()) {
        Log(XORSTR(L"[x] PreSetContext detected unknown trace element!"));
        EliminateThreat(avnContextManipulation, NULL, etTerminate);
        *SkipOriginalCall = TRUE;
        return STATUS_ACCESS_DENIED;
    }
    return STATUS_SUCCESS;
}
#endif

BOOL IsModuleRestricted(LPCWSTR ModuleName) {
    const LPCWSTR RestrictedModules[] = CRITICAL_MODULES;

    BOOL IsLibProtected = FALSE;
    for (const LPCWSTR RestrictedModule : RestrictedModules) {
        if (wcscmp(ModuleName, RestrictedModule) == 0) {
            IsLibProtected = TRUE;
            break;
        }
    }

    return IsLibProtected;
}

#ifdef TIMERED_CHECKINGS
VOID CALLBACK TimerCallback(PVOID Parameter, BOOLEAN TimerOrWaitFired) {
    AvnApi.AvnLock();
    if (!IsAvnStarted) {
        AvnApi.AvnUnlock();
        return;
    }

#ifdef FIND_CHANGED_MODULES
    ValidModulesStorage.FindChangedModules([](const MODULE_INFO& ModuleInfo) -> bool {
        if (IsModuleRestricted(ModuleInfo.Name.c_str())) {
            Log(XORSTR(L"[x] Critical module ") + ModuleInfo.Name + XORSTR(L" was changed!"));
            EliminateThreat(avnCriticalModuleChanged, NULL, etTerminate);
            return true;
        }

        HMODULE hTarget = (HMODULE)ModuleInfo.BaseAddress;
        BOOL ValidModulesHooked = TRUE;

        // Проверяем таблицы экспортов:
        PEAnalyzer pe(hTarget, FALSE);
        const EXPORTS_INFO& Exports = pe.GetExportsInfo();
        for (const auto& Export : Exports.Exports) {
            PVOID Source = Export.VA;
            PVOID Destination = FindHookDestination(Source);
            if (Destination == NULL) continue;
            HMODULE hModule = GetModuleBase(Destination);
            if (hModule != NULL) {
                if (!ValidModulesStorage.IsModuleInStorage(hModule)) {
                    Log(
                        XORSTR(L"[x] Unknown destination module: ") +
                        GetModuleName(hTarget) +
                        XORSTR(L"!") +
                        AnsiToWide(Export.Name) +
                        XORSTR(L" -> ") +
                        GetModuleName(hModule) +
                        XORSTR(L"!") +
                        ValToWideHex(Destination, 16)
                    );
                    DisassembleAndLog(Destination, 16);
                    ValidModulesHooked = FALSE;
                }
            }
            else if (!VMStorage.IsMemoryInMap(Destination)) {
                Log(
                    XORSTR(L"[x] Unknown hook destination: ") +
                    GetModuleName(hTarget) +
                    XORSTR(L"!") +
                    AnsiToWide(Export.Name) +
                    XORSTR(L" -> ") +
                    ValToWideHex(Destination, 16)
                );
                DisassembleAndLog(Destination, 16);
                ValidModulesHooked = FALSE;
            }
        }

        // Если перехват совершили из доверенных модулей:
        if (ValidModulesHooked)
            ValidModulesStorage.RecalcModuleHash(hTarget);
        else
            EliminateThreat(avnUnknownInterception, NULL, etTerminate);

        return true;
    });
#endif

#ifdef FIND_UNKNOWN_MEMORY
    EnumerateMemoryRegions(GetCurrentProcess(), [](const PMEMORY_BASIC_INFORMATION MemoryInfo) -> bool {
        if (MemoryInfo->Protect & EXECUTABLE_MEMORY) {
            if (GetModuleBase(MemoryInfo->BaseAddress) == NULL && !VMStorage.IsMemoryInMap(MemoryInfo->BaseAddress)) {
                Log(XORSTR(L"[x] Unknown memory ") + ValToWideHex(MemoryInfo->BaseAddress, 16));
                DisassembleAndLog(MemoryInfo->BaseAddress, 16);
                EliminateThreat(avnUnknownMemoryRegion, NULL, etTerminate);
            }
        }
        return true;
    });
#endif

#ifdef HANDLES_KEEPER
    static HandlesKeeper* hKeeper = NULL;
    if (!hKeeper) hKeeper = new HandlesKeeper();
    if (hKeeper) {
        hKeeper->EnumHandles(
            IsWindowsVistaOrGreater() ? OB_TYPE_PROCESS : OB_TYPE_PROCESS_XP,
            TRUE,
            [](PREMOTE_HANDLE_INFO HandleInfo, OUT PBOOL NeedToCloseSource) -> void {
                *NeedToCloseSource = HandleInfo->RemoteProcessId != HandleInfo->CurrentProcessId;
            }
        );
    }
#endif

    AvnApi.AvnUnlock();
}
#endif


#ifdef STRICT_DACLs
BOOL SetupDACLs() {
    DACL Dacl(GetCurrentProcess());
    const ULONG AccessRights =
        WRITE_DAC | WRITE_OWNER |
        PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION |
        PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_SUSPEND_RESUME;
    Dacl.Deny(sidCurrentUser, AccessRights);
    Dacl.Allow(sidEveryone, ~AccessRights & 0x1FFF);
    Dacl.Allow(sidSystem, PROCESS_ALL_ACCESS);
    Dacl.Allow(sidAdministrators, PROCESS_ALL_ACCESS);
    return Dacl.Apply();
}
#endif

#ifdef TIMERED_CHECKINGS
int timeTstDelay = DEFALT_TIMER_INTERVAL;

int getTstTime() {
	return timeTstDelay;
}
void setTstTime(int time) {
	timeTstDelay = time;
}

BOOL OperateTimeredCheckings(BOOL DesiredState) {
    static HANDLE TimerQueue;
    static HANDLE TimerHandle;
    static BOOL Activated = FALSE;

    if (DesiredState == Activated) return TRUE;

    if (DesiredState) {
        NTSTATUS Status;
        if (NT_SUCCESS(Status = RtlCreateTimerQueue(&TimerQueue))) {
            if (NT_SUCCESS(Status = RtlCreateTimer(
                TimerQueue,
                &TimerHandle,
                TimerCallback,
                NULL,
                TIMER_INTERVAL,
                TIMER_INTERVAL,
                WT_EXECUTELONGFUNCTION
            ))) {
                Log(XORSTR(L"[v] Periodic check enabled"));
                Activated = TRUE;
                return TRUE;
            }
            else {
                Log(XORSTR(L"[x] Unable to create timer: ") + ValToWideHex(Status, 8));
                RtlDeleteTimerQueue(TimerQueue);
            }
        }
        else {
            Log(XORSTR(L"[x] Unable to create timer queue: ") + ValToWideHex(Status, 8));
        }
    }
    else {
        RtlDeleteTimer(TimerQueue, TimerHandle, INVALID_HANDLE_VALUE);
        RtlDeleteTimerQueue(TimerQueue);
        Activated = FALSE;
        return TRUE;
    }
    return FALSE;
}
#endif

BOOL AvnStartDefence() {
    if (IsAvnStarted) return TRUE;

    // For safety purposes, temporal:
    if (!IsWindows7OrGreater()) return TRUE; // It is no more constant things than temporal
    Log(XORSTR(L"[v] Win7 or greater"));

    SwitchThreadsExecutionStatus(Suspend);
    Log(XORSTR(L"[i] All threads were stopped"));

#ifdef STRICT_DACLs
    SetupDACLs();
#endif

#ifdef THREADS_FILTER
    SetupThreadsFilter(NULL, OnThreadCreated);
    Log(XORSTR(L"[v] Threads filter setted up"));
#endif

#ifdef MITIGATIONS
    // Для корректной работы JIT необходимо включить фильтр потоков!
    Mitigations::SetProhibitDynamicCode(TRUE);
    Mitigations::SetThreadAllowedDynamicCode();
    Log(XORSTR(L"[v] Mitigations enabled"));
#endif

#ifdef SKIP_APP_INIT_DLLS
    //if (IsWindows8Point1OrGreater()) PebSetProcessProtected(TRUE, TRUE);
    AppInitDlls::DisableAppInitDlls();
    Log(XORSTR(L"[v] AppInitDlls intercepted"));
#endif

    Sfc::Initialize();
    InitWinTrust();

#ifdef MODULES_FILTER
    ModulesFilter::SetupFilterCallbacks(PreLoadModuleCallback);
    ModulesFilter::SetupNotificationCallbacks(DllNotificationRoutine);
    ModulesFilter::EnableModulesFilter();
    ModulesFilter::EnableDllNotification();
    Log(XORSTR(L"[v] Modules filters setted up"));

#ifdef WINDOWS_HOOKS_FILTER
    SetupWindowsHooksFilter(OnWindowsHookLoadLibrary);
    Log(XORSTR(L"[v] Windows hooks filter setted up"));
#endif
#ifdef STACKTRACE_CHECK
    SetupUnknownTraceLoadCallback(OnUnknownTraceLoadLibrary);
    Log(XORSTR(L"[v] Stacktrace check on loading modules enabled"));
#endif
#endif

#ifdef APC_FILTER
    ApcDispatcher::EnableApcFilter();
    ApcDispatcher::SetupApcCallback([](PVOID ApcProc, PVOID RetAddr) -> BOOL {
        const BOOL IsApcAllowed = GetModuleBase(ApcProc) != NULL;
        Log(IsApcAllowed ? XORSTR(L"[i] Allowed APC queried!") : XORSTR(L"[x] APC disallowed!"));
        if (!IsApcAllowed) EliminateThreat(avnUnknownApcDestination, NULL, etContinue);
        return IsApcAllowed;
    });
    Log(XORSTR(L"[v] APC filters setted up"));
#endif

#ifdef MEMORY_FILTER
    SetupMemoryCallbacks(
        PreNtAllocateVirtualMemory,
        PostNtAllocateVirtualMemory,
        PreNtProtectVirtualMemory,
        PostNtProtectVirtualMemory,
        PreNtFreeVirtualMemory,
        PostNtFreeVirtualMemory
        // PreNtMapViewOfSection,
        // PostNtMapViewOfSection,
        // PreNtUnmapViewOfSection,
        // PostNtUnmapViewOfSection
    );
    Log(XORSTR(L"[v] Memory filter setted up"));
#endif

#ifdef CONTEXT_FILTER
    ContextFilter::SetupContextCallbacks(PreNtContinue, PreSetContext);
    ContextFilter::EnableContextFilter();
    Log(XORSTR(L"[v] Context filter setted up"));
#endif

#ifdef MODULES_FILTER
    ValidModulesStorage.RecalcModulesHashes();
    Log(XORSTR(L"[v] Modules checksums recalculated"));
#endif

#ifdef MEMORY_FILTER
    VMStorage.ReloadMemoryRegions();
    Log(XORSTR(L"[v] Memory regions reloaded"));
#endif

#ifdef SELF_REMAPPING
    RemapAvnExecutableSections();
#endif

    IsAvnStarted = TRUE;

    SwitchThreadsExecutionStatus(Resume);
    Log(XORSTR(L"[i] All threads were resumed"));

#ifdef TIMERED_CHECKINGS
    OperateTimeredCheckings(TRUE);
#endif

#ifdef SKIP_VIRTUAL_INPUT
    VirtualInput::SetupFilter(HkMouse);
    VirtualInput::SetupFilter(HkKeyboard);
#endif

    return TRUE;
}

VOID AvnStopDefence() {
    if (!IsAvnStarted) return;
    AvnApi.AvnLock();

#ifdef SKIP_VIRTUAL_INPUT
    VirtualInput::RemoveFilter(HkMouse);
    VirtualInput::RemoveFilter(HkKeyboard);
#endif

#ifdef TIMERED_CHECKINGS
    OperateTimeredCheckings(FALSE);
#endif

#ifdef CONTEXT_FILTER
    ContextFilter::DisableContextFilter();
#endif

#ifdef APC_FILTER
    ApcDispatcher::DisableApcFilter();
#endif

#ifdef MODULES_FILTER		
    ModulesFilter::DisableDllNotification();
    ModulesFilter::DisableModulesFilter();
#endif

#ifdef THREADS_FILTER
    RemoveThreadsFilter();
#endif

#ifdef MEMORY_FILTER
    RemoveMemoryCallbacks();
#endif

    IsAvnStarted = FALSE;
    AvnApi.AvnUnlock();
}


typedef NTSTATUS(NTAPI *_NtQueueApcThread) (
    IN HANDLE               ThreadHandle,
    IN PIO_APC_ROUTINE      ApcRoutine,
    IN PVOID                ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
    IN ULONG                ApcReserved OPTIONAL
    );
auto NtQueueApcThread = static_cast<_NtQueueApcThread>(hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtQueueApcThread")));

VOID NTAPI ApcInitialization(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
) {
    Log(XORSTR(L"[v] Startup APC delivered"));
    AvnStartDefence();
}

LONG CALLBACK ExceptionHandler(IN PEXCEPTION_POINTERS ExceptionInfo) {
    const auto ExceptionRecord = ExceptionInfo->ExceptionRecord;
    if (GetModuleBase(ExceptionRecord->ExceptionAddress) != hModules::hCurrent()) return EXCEPTION_CONTINUE_SEARCH;
    Log(
        std::wstring(XORSTR(L"[x] Exception catched!\r\n")) +
        XORSTR(L"\tCode: ") + ValToWideHex(ExceptionRecord->ExceptionCode, 8) + L"\r\n" +
        XORSTR(L"\tAddress: ") + ValToWideHex(ExceptionRecord->ExceptionAddress, sizeof(SIZE_T) * 2) +
        XORSTR(L"\tModule: ") + GetModuleName(ExceptionRecord->ExceptionAddress)
    );
    DisassembleAndLog(ExceptionRecord->ExceptionAddress, 8);
    return EXCEPTION_CONTINUE_SEARCH;
}

VOID WINAPI AvnInit(HMODULE hModule, DWORD dwReason, LPCONTEXT lpContext) {
    //AddVectoredExceptionHandler(TRUE, ExceptionHandler);
    Log(XORSTR(L"[v] Avn initial phase"));
    hModules::_hCurrent = hModule;
    IsAvnStaticLoaded = (lpContext != NULL);
    AvnInitializeApi();
    if (IsAvnStaticLoaded) NtQueueApcThread(
        NtCurrentThread(),
        static_cast<PIO_APC_ROUTINE>(ApcInitialization),
        static_cast<PVOID>(hModule),
        NULL,
        0
    );
}

VOID WINAPI AvnDeinit() {
    AvnStopDefence();
    Log(XORSTR(L"[v] Avn shutted down. Good bye!"));
}

__declspec(code_seg(".stub"))
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPCONTEXT lpContext) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        typedef VOID(WINAPI *_AvnInit)(HMODULE hModule, DWORD dwReason, LPCONTEXT Context);

#ifdef _AMD64_
        AsmJIT JIT(asmjit::ArchInfo::kIdX64);
        JIT.Add(XORSTR("mov rax, ") + ValToAnsiStr(reinterpret_cast<SIZE_T>(AvnInit)));
        JIT.Add(XORSTR("jmp rax"));
#else
        AsmJIT JIT(asmjit::ArchInfo::kIdX86);
        JIT.Add(XORSTR("mov eax, ") + ValToAnsiStr((SIZE_T)AvnInit));
        JIT.Add(XORSTR("jmp eax"));
#endif
        JIT.Build();
        static_cast<_AvnInit>(JIT.MakeCallable())(hModule, dwReason, lpContext);
        break;
    }

    case DLL_PROCESS_DETACH: {
        AvnDeinit();
        break;
    }
    }

    return TRUE;
}

