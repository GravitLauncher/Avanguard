#pragma once

#include "HeapManager.h"

#include <Psapi.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <winternl.h>
#include <ntstatus.h>
#pragma warning(pop)

#pragma comment(lib, "ntdll.lib")

typedef enum _OB_TYPES {
    OB_TYPE_ALL = -1,
    OB_TYPE_PROCESS_XP = 5,
    OB_TYPE_PROCESS = 7,
} OB_TYPES, *POB_TYPES;

typedef struct _REMOTE_HANDLE_INFO {
    HANDLE hRemoteProcess;
    HANDLE hCurrentProcess;
    HANDLE hObject;
    ULONG RemoteProcessId;
    ULONG CurrentProcessId;
    ULONG GrantedAccess;
    ULONG HandleAttributes;
    USHORT ObjectType;
} REMOTE_HANDLE_INFO, *PREMOTE_HANDLE_INFO;

typedef VOID (__fastcall *_EnumHandlesCallback)(PREMOTE_HANDLE_INFO HandleInfo, OUT PBOOL NeedToCloseSource);

class HandlesKeeper {
private:
    const ULONG HeapGranularity = 0x200000;
    HEAP_MEMBLOCK MemBlock = { 0 };

    HANDLE hCurrentProcess = GetCurrentProcess();
    ULONG CurrentProcessId = GetCurrentProcessId();
public:	
    HandlesKeeper();
    ~HandlesKeeper();

    NTSTATUS EnumHandles(OB_TYPES Type, BOOL SkipSelfHandles, _EnumHandlesCallback Callback);
};