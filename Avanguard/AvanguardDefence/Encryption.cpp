#include "stdafx.h"
#include "Encryption.h"

#define UNLOCK_MEM(Address, Size, pOldProtect) VirtualProtect((Address), (Size), PAGE_EXECUTE_READWRITE, (pOldProtect))
#define RESTORE_MEM(Address, Size, OldProtect) VirtualProtect((Address), (Size), (OldProtect), (&OldProtect))

PVOID FASTCALL FindSignature(PVOID StartAddress, PVOID Signature) {
    UINT64	CryptHigh = *(PUINT64)Signature;
    ULONG	CryptLow = *(PULONG)((PUINT64)Signature + 1);
    PBYTE Address = (PBYTE)StartAddress;
    while ((*(PUINT64)Address != CryptHigh) || (*(PULONG)(Address + 8) != CryptLow)) Address++;
    return Address;
}

VOID FORCEINLINE FASTCALL FastXOR(PCODE_BLOCK_INFO CodeBlock) {
    PBYTE DataFinalAddress = (PBYTE)CodeBlock->Address + CodeBlock->Size;
    for (PBYTE pData = (PBYTE)CodeBlock->Address; pData < DataFinalAddress; pData++) {
        *pData ^= ENCRYPTION_KEY;
    }
}


enum RELOCS_SWITCH_TYPE {
    AddRelocs,
    SubRelocs
};

VOID FORCEINLINE FASTCALL FixupRelocs(RELOCS_SET &RelocsSet, RELOCS_SWITCH_TYPE SwitchType) {
    DWORD Delta = (DWORD)ModuleInfo.Delta;

    switch (SwitchType) {
    case AddRelocs:
        for (PDWORD Address : RelocsSet) {
            *Address += Delta;
        }
        break;

    case SubRelocs:
        for (PDWORD Address : RelocsSet) {
            *Address -= Delta;
        }
        break;
    }
}

VOID FASTCALL EncryptDecrypt(PCODE_BLOCK_INFO CodeBlock, RELOCS_SET &RelocsSet) {
#ifndef CODEPAGES_ARE_WRITEABLE
    DWORD OldProtect;
    UNLOCK_MEM(CodeBlock->Address, CodeBlock->Size, &OldProtect);
#endif

    FixupRelocs(RelocsSet, SubRelocs);
    FastXOR(CodeBlock);
    FixupRelocs(RelocsSet, AddRelocs);

#ifndef CODEPAGES_ARE_WRITEABLE
    RESTORE_MEM(CodeBlock->Address, CodeBlock->Size, OldProtect);
#endif
}
