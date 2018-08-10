#pragma once

#include <Windows.h>
#include <vector>
#include "PEUtils.h"

#define ENABLE_ENCRYPTION

#define ENCRYPTION_KEY 0xAA

PVOID FASTCALL FindSignature(PVOID StartAddress, PVOID Signature);

VOID FASTCALL EncryptDecrypt(PCODE_BLOCK_INFO CodeBlock, RELOCS_SET &RelocsSet);

#ifdef ENABLE_ENCRYPTION

#define $90 __nop();
#define $CC __debugbreak();

#define CRYPT_SIGNATURE_BEGIN	$CC $CC $90 $90 $CC $90 $CC $90 $CC $CC $90 $90
#define CRYPT_SIGNATURE_END		$90 $90 $CC $CC $90 $CC $90 $CC $90 $90 $CC $CC 

#ifdef _AMD64_

#define CRYPT_SIG_LENGTH 12
const unsigned char
CryptSigStart[CRYPT_SIG_LENGTH] = { 0xCC, 0xCC, 0x90, 0x90, 0xCC, 0x90, 0xCC, 0x90, 0xCC, 0xCC, 0x90, 0x90 },
CryptSigStop[CRYPT_SIG_LENGTH] = { 0x90, 0x90, 0xCC, 0xCC, 0x90, 0xCC, 0x90, 0xCC, 0x90, 0x90, 0xCC, 0xCC };

VOID FORCEINLINE InsertTrampoline(PVOID From, PVOID To) {
    // Relative Jump (E9 XX XX XX XX):
#define TRAMPOLINE_LENGTH 5

#ifndef CODEPAGES_ARE_WRITEABLE
    DWORD OldProtect;
    VirtualProtect(From, TRAMPOLINE_LENGTH, PAGE_EXECUTE_READWRITE, &OldProtect);
#endif
    ULONG RelJmp32Offset = (ULONG)((SIZE_T)To - (SIZE_T)From - TRAMPOLINE_LENGTH);
    *(PBYTE)From = 0xE9;
    *(PULONG)((PBYTE)From + 1) = RelJmp32Offset;

#undef TRAMPOLINE_LENGTH
}

#define ENCRYPT_START(BlockID)																				\
    static volatile BOOL Initialized##BlockID = FALSE;														\
    static BOOL IsEncrypted##BlockID = FALSE, CSInitialized##BlockID = FALSE;								\
    static CRITICAL_SECTION CriticalSection##BlockID;														\
    static RELOCS_SET RelocsSet##BlockID;																	\
    static CODE_BLOCK_INFO CodeBlock##BlockID;																\
    if (!(BOOL)InterlockedCompareExchange((PULONG)&Initialized##BlockID, (ULONG)TRUE, (ULONG)FALSE)) {		\
        InitializeCriticalSection(&CriticalSection##BlockID);												\
        EnterCriticalSection(&CriticalSection##BlockID);													\
        CSInitialized##BlockID = TRUE;																		\
        CONTEXT Context##BlockID;																			\
        RtlCaptureContext(&Context##BlockID);																\
        PVOID StartAddress##BlockID = FindSignature((PVOID)Context##BlockID.Rip, (PVOID)&CryptSigStart);	\
        PVOID CodeAddress##BlockID = (PVOID)((PBYTE)StartAddress##BlockID + CRYPT_SIG_LENGTH);				\
        PVOID StopAddress##BlockID = FindSignature(CodeAddress##BlockID, (PVOID)&CryptSigStop);				\
        SIZE_T CodeSize##BlockID = (SIZE_T)StopAddress##BlockID - (SIZE_T)CodeAddress##BlockID;				\
        CodeBlock##BlockID.Address = CodeAddress##BlockID;													\
        CodeBlock##BlockID.Size = CodeSize##BlockID;														\
        InsertTrampoline(StartAddress##BlockID, CodeAddress##BlockID);										\
        InsertTrampoline(StopAddress##BlockID, (PVOID)((PBYTE)StopAddress##BlockID + CRYPT_SIG_LENGTH));	\
        FillRelocsSet(&CodeBlock##BlockID, RelocsSet##BlockID);												\
    } else {																								\
        while (!CSInitialized##BlockID);																	\
        EnterCriticalSection(&CriticalSection##BlockID);													\
    }																										\
    if (!IsEncrypted##BlockID) EncryptDecrypt(&CodeBlock##BlockID, RelocsSet##BlockID);						\
    IsEncrypted##BlockID = TRUE;																			\
    CRYPT_SIGNATURE_BEGIN;																					

#define ENCRYPT_END(BlockID)																				\
    CRYPT_SIGNATURE_END;																					\
    if (IsEncrypted##BlockID) EncryptDecrypt(&CodeBlock##BlockID, RelocsSet##BlockID);						\
    IsEncrypted##BlockID = FALSE;																			\
    LeaveCriticalSection(&CriticalSection##BlockID);

#define ENCRYPT(BlockID, Code)	\
    ENCRYPT_START(BlockID);		\
    Code;						\
    ENCRYPT_END(BlockID);

#endif

#ifdef _X86_

#define ENCRYPT_START(BlockID)																				\
    static volatile BOOL Initialized##BlockID = FALSE;														\
    static BOOL IsEncrypted##BlockID = FALSE, CSInitialized##BlockID = FALSE;								\
    static CRITICAL_SECTION CriticalSection##BlockID;														\
    static CODE_BLOCK_INFO CodeBlock##BlockID;																\
    static RELOCS_SET RelocsSet##BlockID;																	\
    if (!(BOOL)InterlockedCompareExchange((PULONG)&Initialized##BlockID, (ULONG)TRUE, (ULONG)FALSE)) {		\
        InitializeCriticalSection(&CriticalSection##BlockID);												\
        EnterCriticalSection(&CriticalSection##BlockID);													\
        CSInitialized##BlockID = TRUE;																		\
        PVOID StartAddress##BlockID, StopAddress##BlockID;													\
        __asm { mov StartAddress##BlockID, offset Start##BlockID }											\
        __asm { mov StopAddress##BlockID, offset SigStop##BlockID }											\
        ULONG CodeSize##BlockID = (ULONG)StopAddress##BlockID - (ULONG)StartAddress##BlockID;				\
        CodeBlock##BlockID.Address	= StartAddress##BlockID;												\
        CodeBlock##BlockID.Size		= CodeSize##BlockID;													\
        FillRelocsSet(&CodeBlock##BlockID, RelocsSet##BlockID);												\
    } else {																								\
        while (!CSInitialized##BlockID);																	\
        EnterCriticalSection(&CriticalSection##BlockID);													\
    }																										\
    if (!IsEncrypted##BlockID) EncryptDecrypt(&CodeBlock##BlockID, RelocsSet##BlockID);						\
    IsEncrypted##BlockID = TRUE;																			\
    goto Start##BlockID;																					\
    CRYPT_SIGNATURE_BEGIN;																					\
Start##BlockID:

#define ENCRYPT_END(BlockID)																				\
    goto Stop##BlockID;																						\
SigStop##BlockID:																							\
    CRYPT_SIGNATURE_END;																					\
Stop##BlockID:																								\
    if (IsEncrypted##BlockID) EncryptDecrypt(&CodeBlock##BlockID, RelocsSet##BlockID);						\
    IsEncrypted##BlockID = FALSE;																			\
    LeaveCriticalSection(&CriticalSection##BlockID);

#define ENCRYPT(BlockID, Code)	\
    ENCRYPT_START(BlockID);		\
    Code;						\
    ENCRYPT_END(BlockID);

#endif

#else
#define ENCRYPT_START(BlockID)
#define ENCRYPT_END(BlockID)
#define ENCRYPT(BlockID, Code) Code;
#endif