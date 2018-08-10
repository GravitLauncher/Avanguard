#pragma once

#include "MemoryFilter.h"
#include "MemoryStorage.h"
#include "Mitigations.h"

extern MemoryStorage VMStorage;

NTSTATUS NTAPI PreNtAllocateVirtualMemory(
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
);

NTSTATUS NTAPI PostNtAllocateVirtualMemory(
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
);

NTSTATUS NTAPI PreNtProtectVirtualMemory(
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PULONG		NumberOfBytesToProtect,
    IN		ULONG		NewAccessProtection,
    OUT		PULONG		OldAccessProtection
);

NTSTATUS NTAPI PostNtProtectVirtualMemory(
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PULONG		NumberOfBytesToProtect,
    IN		ULONG		NewAccessProtection,
    OUT		PULONG		OldAccessProtection
);

NTSTATUS NTAPI PreNtFreeVirtualMemory(
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		FreeType
);

NTSTATUS NTAPI PostNtFreeVirtualMemory(
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		FreeType
);

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
);

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
);

NTSTATUS NTAPI PreNtUnmapViewOfSection(
    OUT			PBOOL	SkipOriginalCall,
    IN			HANDLE	ProcessHandle,
    IN OPTIONAL	PVOID	BaseAddress
);

NTSTATUS NTAPI PostNtUnmapViewOfSection(
    IN			NTSTATUS	ReturnValue,
    IN			HANDLE		ProcessHandle,
    IN OPTIONAL	PVOID		BaseAddress
);
*/