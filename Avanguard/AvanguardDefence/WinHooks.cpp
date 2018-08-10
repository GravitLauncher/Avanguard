#include "stdafx.h"
#include "WinHooks.h"

#include "../HoShiMin's API/DisasmHelper.h"

SIZE_T GetFuncSize(PVOID BaseAddress, unsigned int InstructionsCount) {
    SIZE_T Result = 0;
    disassemble([&](void* Code, void* BaseAddress, unsigned int InstructionLength, char* Disassembly) -> bool {
        Result += InstructionLength;
        return strstr(Disassembly, "ret") == 0;
    }, BaseAddress, BaseAddress, InstructionsCount);
    return Result;
}

BOOL WinHooks::Initialized = FALSE;
PVOID WinHooks::__ClientLoadLibrary = NULL;
std::vector<PVOID> WinHooks::KernelCallbacks;

BOOL WinHooks::Initialize() {
    if (Initialized) return TRUE;

    PVOID* KernelCallbackTable = (PVOID*)(GetPEB()->KernelCallbackTable);
    if (KernelCallbackTable == NULL) return FALSE;

    HMODULE hModule = GetModuleBase(*KernelCallbackTable);
    if (hModule == NULL) return FALSE;

    for (unsigned int i = 0; GetModuleBase(KernelCallbackTable[i]) == hModule; i++)
        KernelCallbacks.emplace_back(KernelCallbackTable[i]);
    std::sort(KernelCallbacks.begin(), KernelCallbacks.end());

    return Initialized = KernelCallbacks.size() > 0;
}

BOOL WinHooks::IsCalledFromWinHook() {
    if (!Initialized && !Initialize()) return FALSE;

    BOOL Status = FALSE;

    const int TracesCount = 50; // Max is USHRT_MAX

    PVOID Ptrs[TracesCount];
    USHORT Captured = CaptureStackBackTrace(0, TracesCount, Ptrs, NULL);

    if (__ClientLoadLibrary) {
        for (unsigned short i = 0; i < Captured; i++) if (Ptrs[i] == __ClientLoadLibrary) {
            Status = TRUE;
            goto AddressFound;
        }
    } else {
        for (unsigned short i = 0; i < Captured; i++) {
            PVOID Address = Ptrs[i];
            for (unsigned int j = 0; j < KernelCallbacks.size() - 1; j++) {
                if (
                    ((SIZE_T)Address >= (SIZE_T)KernelCallbacks[j]) && 
                    ((SIZE_T)Address < (SIZE_T)KernelCallbacks[j] + GetFuncSize(KernelCallbacks[j], 999999))
                ) {
                    Status = TRUE;
                    __ClientLoadLibrary = Address;
                    goto AddressFound;
                }
            }
        }
    }
AddressFound:
    return Status;
}