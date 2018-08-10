#include "stdafx.h"
#include "ModulesUtils.h"

HMODULE GetModuleBase(PVOID Pointer) {
    HMODULE hModule = NULL;
    EnumerateModules([&](const NTDEFINES::PLDR_MODULE Module) -> bool {
        bool Status = 
            Pointer >= Module->BaseAddress && 
            Pointer < static_cast<PBYTE>(Module->BaseAddress) + Module->SizeOfImage;
        if (Status) hModule = static_cast<HMODULE>(Module->BaseAddress);
        return !Status;
    });

    return hModule;
/*
    BOOL Status = GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)Pointer,
        &hModule
    );
    return Status ? hModule : NULL;
*/
}

std::wstring GetModuleName(PVOID AddressOrBase) {
    std::wstring Result;
    EnumerateModules([&](const NTDEFINES::PLDR_MODULE Module) -> bool {
        bool Status = 
            AddressOrBase >= Module->BaseAddress && 
            AddressOrBase < static_cast<PBYTE>(Module->BaseAddress) + Module->SizeOfImage;
        PUNICODE_STRING String = &Module->BaseDllName;
        ULONG Length = String->Length / 2;
        if (Status && String->Buffer && Length) {
            Result.resize(Length);
            CopyMemory(const_cast<LPWSTR>(Result.c_str()), String->Buffer, Length * sizeof(WCHAR));
        }
        return !Status;
    });
    return Result;
}

std::wstring GetModulePath(PVOID AddressOrBase) {
    std::wstring Result;
    EnumerateModules([&](const NTDEFINES::PLDR_MODULE Module) -> bool {
        bool Status = 
            AddressOrBase >= Module->BaseAddress && 
            AddressOrBase < static_cast<PBYTE>(Module->BaseAddress) + Module->SizeOfImage;
        PUNICODE_STRING String = &Module->FullDllName;
        ULONG Length = String->Length / 2;
        if (Status && String->Buffer && Length) {
            Result.resize(Length);
            wcscpy_s(const_cast<LPWSTR>(Result.c_str()), Length, String->Buffer);
        }
        return !Status;
    });
    return Result;
}

void EnumerateModules(EnumerateModulesCallback Callback) {
    if (Callback == NULL) return;

    NTDEFINES::PPEB Peb = GetPEB();
    NTDEFINES::PPEB_LDR_DATA LdrData = (NTDEFINES::PPEB_LDR_DATA)Peb->Ldr;

    NTDEFINES::PLDR_MODULE ListEntry = (NTDEFINES::PLDR_MODULE)LdrData->InLoadOrderModuleList.Flink;
    while (ListEntry && ListEntry->BaseAddress) {
        if (!Callback(ListEntry)) break;
        ListEntry = (NTDEFINES::PLDR_MODULE)ListEntry->InLoadOrderModuleList.Flink;
    }
}