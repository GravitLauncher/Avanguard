#include "stdafx.h"
#include "MemoryFilter.h"


// Because of possible loader-locks we shouldn't filtrate the NtMap[Unmap]ViewOfSection!
/*
FILTRATION(
    NTSTATUS, NTAPI, NtMapViewOfSection,
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
    FILTRATE(
        NTSTATUS, Status, NtMapViewOfSection,
        SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, 
        SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect
    );
    return Status;
}

FILTRATION(
    NTSTATUS, NTAPI, NtUnmapViewOfSection,
    IN			HANDLE ProcessHandle,
    IN OPTIONAL	PVOID  BaseAddress
) {
    FILTRATE(
        NTSTATUS, Status, NtUnmapViewOfSection, 
        ProcessHandle, BaseAddress
    );
    return Status;
}
*/

FILTRATION(
    NTSTATUS, NTAPI, NtAllocateVirtualMemory,
    IN		HANDLE		ProcessHandle,
    IN OUT	PVOID*		BaseAddress,
    IN		ULONG_PTR	ZeroBits,
    IN OUT	PSIZE_T		RegionSize,
    IN		ULONG		AllocationType,
    IN		ULONG		Protect
) {
    FILTRATE(
        NTSTATUS, Status, NtAllocateVirtualMemory,
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect
    );
    return Status;
}



FILTRATION(
    NTSTATUS, NTAPI, NtProtectVirtualMemory,
    IN		HANDLE	ProcessHandle,
    IN OUT	PVOID*	BaseAddress,
    IN OUT	PULONG	NumberOfBytesToProtect,
    IN		ULONG	NewAccessProtection,
    OUT		PULONG	OldAccessProtection
) {
    FILTRATE(
        NTSTATUS, Status, NtProtectVirtualMemory,
        ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection
    );
    return Status;
}

FILTRATION(
    NTSTATUS, NTAPI, NtFreeVirtualMemory,
    IN		HANDLE	ProcessHandle,
    IN OUT	PVOID*	BaseAddress,
    IN OUT	PSIZE_T	RegionSize,
    IN		ULONG	FreeType
) {
    FILTRATE(
        NTSTATUS, Status, NtFreeVirtualMemory,
        ProcessHandle, BaseAddress, RegionSize, FreeType
    );
    return Status;
}

BOOL IsMemHooksInitialized = FALSE;

const PVOID pNtAllocateVirtualMemory = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtAllocateVirtualMemory"));
const PVOID pNtProtectVirtualMemory = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtProtectVirtualMemory"));
const PVOID pNtFreeVirtualMemory = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtFreeVirtualMemory"));
//const PVOID pNtMapViewOfSection = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtMapViewOfSection"));
//const PVOID pNtUnmapViewOfSection = hModules::QueryAddress(hModules::hNtdll(), XORSTR("NtUnmapViewOfSection"));

HOOK_INFO HooksInfo[] = {
    INTERCEPTION_ENTRY(pNtAllocateVirtualMemory, NtAllocateVirtualMemory),
    INTERCEPTION_ENTRY(pNtProtectVirtualMemory, NtProtectVirtualMemory),
    INTERCEPTION_ENTRY(pNtFreeVirtualMemory, NtFreeVirtualMemory),
    //INTERCEPTION_ENTRY(pNtMapViewOfSection, NtMapViewOfSection),
    //INTERCEPTION_ENTRY(pNtUnmapViewOfSection, NtUnmapViewOfSection)
};

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
) {
    DEFINE_FILTERS(NtAllocateVirtualMemory, AllocPreCallback, AllocPostCallback);
    DEFINE_FILTERS(NtProtectVirtualMemory, ProtectPreCallback, ProtectPostCallback);
    DEFINE_FILTERS(NtFreeVirtualMemory, FreePreCallback, FreePostCallback);
    //DEFINE_FILTERS(NtMapViewOfSection, MapPreCallback, MapPostCallback);
    //DEFINE_FILTERS(NtUnmapViewOfSection, UnmapPreCallback, UnmapPostCallback);

    if (IsMemHooksInitialized) return TRUE;

    IsMemHooksInitialized = HookEmAll(HooksInfo, sizeof(HooksInfo) / sizeof(HOOK_INFO));
    return IsMemHooksInitialized;
}

VOID RemoveMemoryCallbacks() {
    if (IsMemHooksInitialized)
        UnHookEmAll(HooksInfo, sizeof(HooksInfo) / sizeof(HOOK_INFO));
}