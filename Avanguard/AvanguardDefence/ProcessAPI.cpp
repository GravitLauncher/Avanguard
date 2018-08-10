#include "stdafx.h"
#include "ProcessAPI.h"

typedef struct _PROCESS_BASIC_INFORMATION32 {
    ULONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG AffinityMask;
    ULONG BasePriority;
    ULONG UniqueProcessId;
    ULONG ParentProcessId;
} PROCESS_BASIC_INFORMATION32, *PPROCESS_BASIC_INFORMATION32;

typedef struct _PROCESS_BASIC_INFORMATION64 {
    ULONG ExitStatus;
    ULONG Reserved0;
    UINT64 PebBaseAddress;
    UINT64 AffinityMask;
    ULONG BasePriority;
    ULONG Reserved1;
    UINT64 UniqueProcessId;
    UINT64 ParentProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

typedef struct _PROCESS_BASIC_INFORMATION_WOW64 {
    UINT64 Wow64PebBaseAddress;
} PROCESS_BASIC_INFORMATION_WOW64, *PPROCESS_BASIC_INFORMATION_WOW64;


typedef BOOL (WINAPI *_IsWow64Process)(HANDLE hProcess, OUT PBOOL Wow64Process);

BOOL __IsWow64Process__(HANDLE hProcess, OUT PBOOL Wow64Process) {
    _IsWow64Process __IsWow64Process = (_IsWow64Process)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
    return __IsWow64Process ? __IsWow64Process(hProcess, Wow64Process) : FALSE;
}

BOOL Is64BitWindows() {
#ifdef _AMD64_
    return TRUE;
#else
    BOOL Wow64Process;
    return IsWow64Process(GetCurrentProcess(), &Wow64Process) && Wow64Process;
#endif
}

typedef NTSTATUS (NTAPI *_NtWow64QueryInformationProcess64)(
    HANDLE hProcess,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    OUT PUINT64 ReturnLength
);

NTSTATUS NtWow64QueryInformationProcess64(
    HANDLE hProcess, 
    PROCESSINFOCLASS ProcessInformationClass, 
    PVOID ProcessInformation, 
    ULONG ProcessInformationLength,
    OUT PUINT64 ReturnLength
) {
#ifdef _AMD64_
    if (ReturnLength) *ReturnLength = 0;
    return NtQueryInformationProcess(hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationLength, (PULONG)ReturnLength);
#else
    static _NtWow64QueryInformationProcess64
        __NtWow64QueryInformationProcess64 =
        (_NtWow64QueryInformationProcess64)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWow64QueryInformationProcess64");

    if (__NtWow64QueryInformationProcess64 == NULL) return STATUS_UNSUCCESSFUL;

    return __NtWow64QueryInformationProcess64(hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
#endif
}

BOOL Is64BitProcess(HANDLE hProcess) {
    if (Is64BitWindows()) {
        BOOL Wow64Process;
        __IsWow64Process__(hProcess, &Wow64Process);
        return !Wow64Process;
    } else{
        return FALSE;
    }
}

BOOL GetProcessBasicInfo(HANDLE hProcess, OUT PPROCESS_BASIC_INFO ProcessBasicInfo) {
    if (ProcessBasicInfo == NULL) return FALSE;
    
    if (Is64BitProcess(hProcess)) {
        PROCESS_BASIC_INFORMATION64 ProcessBasicInfo64;
        UINT64 ReturnLength;
        NTSTATUS Status = NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &ProcessBasicInfo64, sizeof(ProcessBasicInfo64), &ReturnLength);
        if (Status != STATUS_SUCCESS) return FALSE;

        ProcessBasicInfo->ExitStatus = ProcessBasicInfo64.ExitStatus;
        ProcessBasicInfo->AffinityMask = ProcessBasicInfo64.AffinityMask;
        ProcessBasicInfo->BasePriority = ProcessBasicInfo64.BasePriority;
        ProcessBasicInfo->UniqueProcessId = ProcessBasicInfo64.UniqueProcessId;
        ProcessBasicInfo->ParentProcessId = ProcessBasicInfo64.ParentProcessId;
    } else {
#ifdef _AMD64_
        PROCESS_BASIC_INFORMATION64 ProcessBasicInfoX;
#else
        PROCESS_BASIC_INFORMATION32 ProcessBasicInfoX;
#endif
        ULONG ReturnLength;
        NTSTATUS Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessBasicInfoX, sizeof(ProcessBasicInfoX), &ReturnLength);
        if (Status != STATUS_SUCCESS) return FALSE;
        
        ProcessBasicInfo->ExitStatus = ProcessBasicInfoX.ExitStatus;
        ProcessBasicInfo->AffinityMask = ProcessBasicInfoX.AffinityMask;
        ProcessBasicInfo->BasePriority = ProcessBasicInfoX.BasePriority;
        ProcessBasicInfo->UniqueProcessId = ProcessBasicInfoX.UniqueProcessId;
        ProcessBasicInfo->ParentProcessId = ProcessBasicInfoX.ParentProcessId;
    }

    return TRUE;
}

typedef NTSTATUS (NTAPI *_NtQueryVirtualMemory)(
    IN				HANDLE						ProcessHandle,
    IN OPTIONAL		PVOID						BaseAddress,
    IN				MEMORY_INFORMATION_CLASS	MemoryInformationClass,
    OUT				PVOID						MemoryInformation,
    IN				SIZE_T						MemoryInformationLength,
    OUT OPTIONAL	PSIZE_T						ReturnLength
);

NTSTATUS NTAPI __NtQueryVirtualMemory(
    IN				HANDLE						ProcessHandle,
    IN OPTIONAL		PVOID						BaseAddress,
    IN				MEMORY_INFORMATION_CLASS	MemoryInformationClass,
    OUT				PVOID						MemoryInformation,
    IN				SIZE_T						MemoryInformationLength,
    OUT OPTIONAL	PSIZE_T						ReturnLength
) {
    static _NtQueryVirtualMemory __dNtQueryVirtualMemory = NULL;
    if (__dNtQueryVirtualMemory == NULL) __dNtQueryVirtualMemory = 
        (_NtQueryVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryVirtualMemory");
    return __dNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

VOID EnumerateMemoryRegions(
    HANDLE hProcess, 
    _MapCallback Callback
) {
    if (Callback == NULL) return;
    MEMORY_BASIC_INFORMATION Info;
    SIZE_T Address = NULL;
    SIZE_T ReturnLength = 0;
    while (NT_SUCCESS(__NtQueryVirtualMemory(
        hProcess,
        (PVOID)Address,
        MemoryBasicInformation,
        &Info,
        sizeof(Info),
        &ReturnLength
    ))) {
        if (!Callback(&Info)) return;
        Address += Info.RegionSize;
    }
}

BOOL SwitchThreadsExecutionStatus(EXECUTION_STATUS ExecutionStatus) {
    HANDLE hSnapThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
    if (hSnapThreads == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 ThreadInfo;
    ThreadInfo.dwSize = sizeof(ThreadInfo);

    DWORD CurrentThreadId = GetCurrentThreadId();
    DWORD CurrentProcessId = GetCurrentProcessId();
    if (Thread32First(hSnapThreads, &ThreadInfo)) do {
        if (ThreadInfo.th32OwnerProcessID != CurrentProcessId) continue;
        if (ThreadInfo.th32ThreadID == CurrentThreadId) continue;
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadInfo.th32ThreadID);
        if (hThread == NULL) continue;
        switch (ExecutionStatus) {
        case Suspend:
            SuspendThread(hThread);
            break;
        case Resume:
            ResumeThread(hThread);
            break;
        }
        CloseHandle(hThread);
    } while (Thread32Next(hSnapThreads, &ThreadInfo));

    CloseHandle(hSnapThreads);
    return TRUE;
}

BOOL EnumerateThreads(_ThreadCallback ThreadCallback) {
    HANDLE hSnapThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
    if (hSnapThreads == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 ThreadInfo;
    ThreadInfo.dwSize = sizeof(ThreadInfo);

    ULONG ProcessId = GetCurrentProcessId();
    if (Thread32First(hSnapThreads, &ThreadInfo)) do {
        if (ThreadInfo.th32OwnerProcessID != ProcessId) continue;
        if (!ThreadCallback(ThreadInfo.th32ThreadID)) goto Exit;
    } while (Thread32Next(hSnapThreads, &ThreadInfo));

Exit:
    CloseHandle(hSnapThreads);
    return TRUE;
}