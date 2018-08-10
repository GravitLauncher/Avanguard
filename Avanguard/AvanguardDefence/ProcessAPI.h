#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <functional>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <winternl.h>
#include <ntstatus.h>
#pragma warning(pop)

__forceinline
HANDLE PID2H(ULONG ProcessId, DWORD DesiredAccess = PROCESS_ALL_ACCESS) {
    return OpenProcess(DesiredAccess, FALSE, ProcessId);
}

BOOL Is64BitWindows();
BOOL Is64BitProcess(HANDLE hProcess);

typedef struct _PROCESS_BASIC_INFO {
    ULONG ExitStatus;
    UINT64 AffinityMask;
    ULONG BasePriority;
    UINT64 UniqueProcessId;
    UINT64 ParentProcessId;
} PROCESS_BASIC_INFO, *PPROCESS_BASIC_INFO;

BOOL GetProcessBasicInfo(HANDLE hProcess, OUT PPROCESS_BASIC_INFO ProcessBasicInfo);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef std::function<bool(const PMEMORY_BASIC_INFORMATION)> _MapCallback;

VOID EnumerateMemoryRegions(
    HANDLE hProcess, 
    _MapCallback Callback
);

typedef enum _EXECUTION_STATUS {
    Suspend,
    Resume
} EXECUTION_STATUS, *PEXECUTION_STATUS;

BOOL SwitchThreadsExecutionStatus(EXECUTION_STATUS ExecutionStatus);

typedef std::function<bool(ULONG ThreadId)> _ThreadCallback;
BOOL EnumerateThreads(_ThreadCallback ThreadCallback);

NTSTATUS NTAPI __NtQueryVirtualMemory(
    IN				HANDLE						ProcessHandle,
    IN OPTIONAL		PVOID						BaseAddress,
    IN				MEMORY_INFORMATION_CLASS	MemoryInformationClass,
    OUT				PVOID						MemoryInformation,
    IN				SIZE_T						MemoryInformationLength,
    OUT OPTIONAL	PSIZE_T						ReturnLength
);

#define NtCurrentProcess()	(HANDLE)(-1)
#define NtCurrentThread()	(HANDLE)(-2)

BOOL FORCEINLINE QueryVirtualMemory(
    IN PVOID Address, 
    OUT PMEMORY_BASIC_INFORMATION MemoryInfo
) {
    SIZE_T ReturnLength;
    return NT_SUCCESS(__NtQueryVirtualMemory(
        NtCurrentProcess(),
        Address,
        MemoryBasicInformation,
        MemoryInfo,
        sizeof(MEMORY_BASIC_INFORMATION),
        &ReturnLength
    ));
}