#include "stdafx.h"
#include "ThreadsFilter.h"

#pragma warning(push)
#pragma warning(disable: 4312)

// For the old SDK support:
#if (_WIN32_WINNT <= 0x0603)
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
#endif

namespace {
    BOOL IsThreadsHooksInitialized = FALSE;

    _ThreadCreatedCallback OnThreadCreate = NULL;
    _ValidThreadCreatedCallback OnValidThreadCreate = NULL;

    CSLock Locker;
    std::unordered_set<HANDLE> LocalThreads;

    typedef NTSTATUS(NTAPI *_NtTerminateThread)(HANDLE hThread, NTSTATUS ExitStatus);
    const _NtTerminateThread NtTerminateThread =
        (_NtTerminateThread)hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtTerminateThread"));

    typedef DWORD(WINAPI *_GetThreadId)(HANDLE hProcess);
    const _GetThreadId __GetThreadId = 
        (_GetThreadId)hModules::QueryAddress(hModules::hKernel32(), XORSTR("GetThreadId"));
}



INTERCEPTION(VOID, NTAPI, LdrInitializeThunk, PCONTEXT Context) {
    HANDLE ThreadId = (HANDLE)GetCurrentThreadId();

    Locker.Lock();
    BOOL IsLocalThread = LocalThreads.find(ThreadId) != LocalThreads.end();
    BOOL Allow = OnThreadCreate ? OnThreadCreate(Context, IsLocalThread) : IsLocalThread;
    Locker.Unlock();

    if (!Allow) {
        NtTerminateThread(GetCurrentThread(), 0);
        ZeroMemory(Context, sizeof(*Context));
    }

    OrgnlLdrInitializeThunk(Context);
}

typedef struct _INITIAL_TEB {
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

INTERCEPTION(NTSTATUS, NTAPI, NtCreateThread,
    OUT PHANDLE				ThreadHandle,
    IN ACCESS_MASK			DesiredAccess,
    IN POBJECT_ATTRIBUTES	ObjectAttributes OPTIONAL,
    IN HANDLE				ProcessHandle,
    OUT CLIENT_ID*			ClientId,
    IN PCONTEXT				ThreadContext,
    IN PINITIAL_TEB			InitialTeb,
    IN BOOLEAN				CreateSuspended
) {
    Locker.Lock();

    CLIENT_ID LocalClientId = { 0 };
    NTSTATUS Status = OrgnlNtCreateThread(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        &LocalClientId,
        ThreadContext,
        InitialTeb,
        CreateSuspended
    );

    if (NT_SUCCESS(Status)) {
        HANDLE ThreadId = LocalClientId.UniqueThread;
        LocalThreads.emplace(ThreadId);
#ifdef _AMD64_
        if (OnValidThreadCreate) OnValidThreadCreate(ThreadId, (PVOID)ThreadContext->Rcx, (PVOID)ThreadContext->Rdx);
#else
        if (OnValidThreadCreate) OnValidThreadCreate(ThreadId, (PVOID)ThreadContext->Eax, (PVOID)ThreadContext->Ebx);
#endif
    }
    if (ClientId) *ClientId = LocalClientId;

    Locker.Unlock();

    return Status;
}


typedef struct _THREAD_INTERNAL_INFO {
    ULONG Flags;
    ULONG BufferSize;
    PVOID Buffer;
    ULONG Unknown;
} CLIENT_INFO, TEB_INFO, *PCLIENT_INFO, *PTEB_INFO;

typedef struct _THREAD_INFO {
    ULONG		Length;
    CLIENT_INFO	Client;
    TEB_INFO	TEB;
} THREAD_INFO, *PTHREAD_INFO;

INTERCEPTION(NTSTATUS, NTAPI, NtCreateThreadEx,
    OUT PHANDLE					ThreadHandle,
    IN  ACCESS_MASK				DesiredAccess,
    IN  POBJECT_ATTRIBUTES		ObjectAttributes,
    IN  HANDLE					ProcessHandle,
    IN  LPTHREAD_START_ROUTINE	lpStartAddress,
    IN  LPVOID					lpParameter,
    IN  BOOL					CreateSuspended,
    IN  SIZE_T					StackZeroBits,
    IN  SIZE_T					SizeOfStackCommit,
    IN  SIZE_T					SizeOfstackReserve,
    OUT PTHREAD_INFO			ThreadInfo
) {
    Locker.Lock();

    NTSTATUS Status = OrgnlNtCreateThreadEx(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        lpStartAddress,
        lpParameter,
        CreateSuspended,
        StackZeroBits,
        SizeOfStackCommit,
        SizeOfstackReserve,
        ThreadInfo
    );

    if (NT_SUCCESS(Status) && (GetProcessId(ProcessHandle) == GetCurrentProcessId())) {
        HANDLE ThreadId = (HANDLE)__GetThreadId(*ThreadHandle);
        LocalThreads.emplace(ThreadId);
        if (OnValidThreadCreate) OnValidThreadCreate(ThreadId, lpStartAddress, lpParameter);
    }
    
    Locker.Unlock();
    return Status;
}


INTERCEPTION(NTSTATUS, NTAPI, NtTerminateThread,
    IN HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus
) {
    HANDLE ThreadId = (HANDLE)__GetThreadId(ThreadHandle);
    BOOL IsCurrentThread = ThreadId == (HANDLE)GetCurrentThreadId();

    BOOL ThreadExists;
    Locker.Lock();
    ThreadExists = LocalThreads.find(ThreadId) != LocalThreads.end();
    if (ThreadExists) LocalThreads.erase(ThreadId);
    Locker.Unlock();

    NTSTATUS Status = OrgnlNtTerminateThread(ThreadHandle, ExitStatus);

    if (!NT_SUCCESS(Status)) {
        if (ThreadExists) {
            Locker.Lock();
            LocalThreads.emplace(ThreadId);
            Locker.Unlock();
        }
    }

    return Status;
}


const PVOID pNtCreateThread = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtCreateThread"));
const PVOID pNtCreateThreadEx = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtCreateThreadEx"));
const PVOID pNtTerminateThread = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtTerminateThread"));
const PVOID pLdrInitializeThunk = hModules::QueryAddress(hModules::hNtdll(), XORSTR("LdrInitializeThunk"));

HOOK_INFO ThreadsHooksInfo[] = {
    INTERCEPTION_ENTRY(pLdrInitializeThunk, LdrInitializeThunk),
    INTERCEPTION_ENTRY(pNtCreateThread, NtCreateThread),
    INTERCEPTION_ENTRY(pNtCreateThreadEx, NtCreateThreadEx),
    INTERCEPTION_ENTRY(pNtTerminateThread, NtTerminateThread)
};


BOOL SetupThreadsFilter(
    _ValidThreadCreatedCallback ValidThreadCreatedCallback,
    _ThreadCreatedCallback ThreadCreatedCallback
) {
    OnThreadCreate = ThreadCreatedCallback;
    OnValidThreadCreate = ValidThreadCreatedCallback;

    if (!IsThreadsHooksInitialized) {
        LocalThreads.clear();
        IsThreadsHooksInitialized = HookEmAll(ThreadsHooksInfo, sizeof(ThreadsHooksInfo) / sizeof(ThreadsHooksInfo[0]));
    }
    return IsThreadsHooksInitialized;
}

VOID RemoveThreadsFilter() {
    if (IsThreadsHooksInitialized) 
        UnHookEmAll(ThreadsHooksInfo, sizeof(ThreadsHooksInfo) / sizeof(ThreadsHooksInfo[0]));
    IsThreadsHooksInitialized = FALSE;
}

#pragma warning(pop)