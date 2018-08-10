#include "stdafx.h"
#include "MemoryCallbacks.h"

MemoryStorage VMStorage;

static const ULONG CurrentProcessId = GetCurrentProcessId();

NTSTATUS NTAPI PreNtAllocateVirtualMemory(
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
) {
    return 0;
}

NTSTATUS NTAPI PostNtAllocateVirtualMemory(
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
) {
    if (GetProcessId(ProcessHandle) != CurrentProcessId) return ReturnValue;
    if ((NT_SUCCESS(ReturnValue)) && (Protect & EXECUTABLE_MEMORY))
        VMStorage.ProcessAllocation(*BaseAddress);
    return ReturnValue;
}



NTSTATUS NTAPI PreNtProtectVirtualMemory(
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PULONG		NumberOfBytesToProtect,
    IN		ULONG		NewAccessProtection,
    OUT		PULONG		OldAccessProtection
) {
    return 0;
}

NTSTATUS NTAPI PostNtProtectVirtualMemory(
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PULONG		NumberOfBytesToProtect,
    IN		ULONG		NewAccessProtection,
    OUT		PULONG		OldAccessProtection
) {
    if (GetProcessId(ProcessHandle) != CurrentProcessId) return ReturnValue;
    if (NT_SUCCESS(ReturnValue)) {
        // Неисполняемую сделали исполняемой:
        if ((NewAccessProtection & EXECUTABLE_MEMORY) && !(*OldAccessProtection & EXECUTABLE_MEMORY)) {
            VMStorage.ProcessAllocation(*BaseAddress);
        }
/*
        else
        // Исполняемую сделали неисполняемой:
        if (!(NewAccessProtection & EXECUTABLE_MEMORY) && (*OldAccessProtection & EXECUTABLE_MEMORY)) {
            VMStorage.ProcessFreeing(*BaseAddress);
        }
*/
    }
    return ReturnValue;
}



NTSTATUS NTAPI PreNtFreeVirtualMemory(
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		FreeType
) {
    return 0;
}

NTSTATUS NTAPI PostNtFreeVirtualMemory(
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		FreeType
) {
    if (GetProcessId(ProcessHandle) != CurrentProcessId) return ReturnValue;
    if (FreeType != MEM_RELEASE) return ReturnValue;
    if (NT_SUCCESS(ReturnValue))
        VMStorage.ProcessFreeing(*BaseAddress);
    return ReturnValue;
}

/*
NTSTATUS NTAPI PreNtMapViewOfSection(
    OUT				PBOOL			SkipOriginalCall,
    IN				HANDLE			SectionHandle,
    IN				HANDLE			ProcessHandle,
    IN OUT			PVOID*			BaseAddress,
    IN				ULONG_PTR		ZeroBits,
    IN				SIZE_T			CommitSize,
    IN OUT OPTIONAL	PLARGE_INTEGER	SectionOffset,
    IN OUT			PSIZE_T			ViewSize,
    IN				SECTION_INHERIT	InheritDisposition,
    IN				ULONG			AllocationType,
    IN				ULONG			Win32Protect
) {
    return 0;
}

NTSTATUS NTAPI PostNtMapViewOfSection(
    IN				NTSTATUS		ReturnValue,
    IN				HANDLE			SectionHandle,
    IN				HANDLE			ProcessHandle,
    IN OUT			PVOID*			BaseAddress,
    IN				ULONG_PTR		ZeroBits,
    IN				SIZE_T			CommitSize,
    IN OUT OPTIONAL	PLARGE_INTEGER	SectionOffset,
    IN OUT			PSIZE_T			ViewSize,
    IN				SECTION_INHERIT	InheritDisposition,
    IN				ULONG			AllocationType,
    IN				ULONG			Win32Protect
) {
    if (GetProcessId(ProcessHandle) != CurrentProcessId) return ReturnValue;
    if ((NT_SUCCESS(ReturnValue)) && (Win32Protect & EXECUTABLE_MEMORY)) {
        VMStorage.ProcessAllocation(*BaseAddress);
    }
    return ReturnValue;
}


NTSTATUS NTAPI PreNtUnmapViewOfSection(
    OUT			PBOOL	SkipOriginalCall,
    IN			HANDLE	ProcessHandle,
    IN OPTIONAL	PVOID	BaseAddress
) {
    return 0;
}

NTSTATUS NTAPI PostNtUnmapViewOfSection(
    IN			NTSTATUS	ReturnValue,
    IN			HANDLE		ProcessHandle,
    IN OPTIONAL	PVOID		BaseAddress
) {
    if (GetProcessId(ProcessHandle) != CurrentProcessId) return ReturnValue;
    if (NT_SUCCESS(ReturnValue))
        VMStorage.ProcessFreeing(BaseAddress);
    return ReturnValue;
}
*/