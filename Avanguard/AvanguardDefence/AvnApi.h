#pragma once

#include <Windows.h>
#include "ThreatTypes.h"

typedef BOOL    (WINAPI *_AvnStart)();
typedef VOID    (WINAPI *_AvnStop)();
typedef BOOL    (WINAPI *_AvnIsStarted)();
typedef BOOL    (WINAPI *_AvnIsStaticLoaded)();
typedef VOID    (WINAPI *_AvnRegisterThreatNotifier)(OPTIONAL _AvnThreatNotifier Notifier);
typedef VOID    (WINAPI *_AvnEliminateThreat)(AVN_THREAT Threat, OPTIONAL PVOID Data);
typedef VOID    (WINAPI *_AvnLock)();
typedef VOID    (WINAPI *_AvnUnlock)();
typedef VOID    (WINAPI *_AvnRehashModule)(HMODULE hModule);
typedef BOOL    (WINAPI *_AvnIsModuleValid)(HMODULE hModule);
typedef BOOL    (WINAPI *_AvnIsFileProtected)(LPCWSTR FilePath);
typedef BOOL    (WINAPI *_AvnIsFileSigned)(LPCWSTR FilePath, BOOL CheckRevocation);
typedef BOOL    (WINAPI *_AvnVerifyEmbeddedSignature)(LPCWSTR FilePath);
typedef BOOL    (WINAPI *_AvnIsAddressAllowed)(PVOID Address, BOOL IncludeJitMemory);
typedef UINT64  (WINAPI *_AvnGetCpuid)();
typedef UINT64  (WINAPI *_AvnGetSmbiosId)();
typedef UINT64  (WINAPI *_AvnGetMacId)();
typedef UINT64  (WINAPI *_AvnGetHddId)();
typedef UINT64  (WINAPI *_AvnHash)(PVOID Data, ULONG Size);

typedef struct _AVN_API {
    _AvnStart                   AvnStart;                   // Synchronized
    _AvnStop                    AvnStop;                    // Synchronized
    _AvnIsStarted               AvnIsStarted;               // Doesn't need synchronization
    _AvnIsStaticLoaded          AvnIsStaticLoaded;          // Doesn't need synchronization
    _AvnRegisterThreatNotifier  AvnRegisterThreatNotifier;  // Doesn't need synchronization
    _AvnEliminateThreat         AvnEliminateThreat;         // Doesn't need synchronization
    _AvnLock                    AvnLock;
    _AvnUnlock                  AvnUnlock;
    _AvnRehashModule            AvnRehashModule;
    _AvnIsModuleValid           AvnIsModuleValid;
    _AvnIsFileProtected         AvnIsFileProtected;
    _AvnIsFileSigned            AvnIsFileSigned;
    _AvnVerifyEmbeddedSignature AvnVerifyEmbeddedSignature;
    _AvnIsAddressAllowed        AvnIsAddressAllowed;
    _AvnGetCpuid                AvnGetCpuid;                 // Doesn't need synchronization
    _AvnGetSmbiosId             AvnGetSmbiosId;              // Doesn't need synchronization
    _AvnGetMacId                AvnGetMacId;                 // Doesn't need synchronization
    _AvnGetHddId                AvnGetHddId;                 // Doesn't need synchronization
    _AvnHash                    AvnHash;                     // Doesn't need synchronization
} AVN_API, *PAVN_API;