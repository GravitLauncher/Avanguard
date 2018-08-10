#pragma once

#include "hModules.h"
#include "..\\HoShiMin's API\\HookHelper.h"

typedef NTSTATUS (CALLBACK *_AllocMemoryPreCallback) (
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
);

typedef NTSTATUS (CALLBACK *_AllocMemoryPostCallback) (
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
);


typedef NTSTATUS (CALLBACK *_ProtectMemoryPreCallback) (
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PULONG		NumberOfBytesToProtect,
    IN		ULONG		NewAccessProtection,
    OUT		PULONG		OldAccessProtection
);

typedef NTSTATUS (CALLBACK *_ProtectMemoryPostCallback) (
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PULONG		NumberOfBytesToProtect,
    IN		ULONG		NewAccessProtection,
    OUT		PULONG		OldAccessProtection
);


typedef NTSTATUS (CALLBACK *_FreeMemoryPreCallback) (
    OUT		PBOOL		SkipOriginalCall,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		FreeType
);

typedef NTSTATUS (CALLBACK *_FreeMemoryPostCallback) (
    IN		NTSTATUS	ReturnValue,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		FreeType
);

// Because of possible loader-locks we shouldn't filtrate the NtMap[Unmap]ViewOfSection!
/*
enum SECTION_INHERIT {
    ViewShare,
    ViewUnmap
};

typedef NTSTATUS (CALLBACK *_MapMemoryPreCallback) (
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

typedef NTSTATUS (CALLBACK *_MapMemoryPostCallback) (
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

typedef NTSTATUS (CALLBACK *_UnmapMemoryPreCallback) (
    OUT			PBOOL	SkipOriginalCall,
    IN			HANDLE	ProcessHandle,
    IN OPTIONAL	PVOID	BaseAddress
);

typedef NTSTATUS (CALLBACK *_UnmapMemoryPostCallback) (
    IN			NTSTATUS	ReturnValue,
    IN			HANDLE		ProcessHandle,
    IN OPTIONAL	PVOID		BaseAddress
);
*/


BOOL SetupMemoryCallbacks(
    _AllocMemoryPreCallback		AllocPreCallback,
    _AllocMemoryPostCallback	AllocPostCallback,
    _ProtectMemoryPreCallback	ProtectPreCallback,
    _ProtectMemoryPostCallback	ProtectPostCallback,
    _FreeMemoryPreCallback		FreePreCallback,
    _FreeMemoryPostCallback		FreePostCallback
    //_MapMemoryPreCallback		MapPreCallback,
    //_MapMemoryPostCallback	MapPostCallback,
    //_UnmapMemoryPreCallback	UnmapPreCallback,
    //_UnmapMemoryPostCallback	UnmapPostCallback
);

VOID RemoveMemoryCallbacks();