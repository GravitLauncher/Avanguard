#include "stdafx.h"
#include "HandlesKeeper.h"

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

#pragma warning(push)
#pragma warning(disable: 4200)
typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[0];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
#pragma warning(pop)

#define SystemExtendedHandleInformation 0x40

HandlesKeeper::HandlesKeeper() {
    AllocReAllocFreeHeap(&MemBlock, HeapGranularity);
}

HandlesKeeper::~HandlesKeeper() {
    AllocReAllocFreeHeap(&MemBlock, 0);
}

NTSTATUS HandlesKeeper::EnumHandles(OB_TYPES Type, BOOL SkipSelfHandles, _EnumHandlesCallback Callback) {
    if (Callback == NULL) return STATUS_SUCCESS;

    NTSTATUS Status;

    ULONG ReturnLength;
    while (
        Status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
            MemBlock.Buffer,
            MemBlock.Size,
            &ReturnLength
        )
        ==
        STATUS_INFO_LENGTH_MISMATCH
    ) {
        AllocReAllocFreeHeap(&MemBlock, MemBlock.Size + HeapGranularity);
    }

    if (Status != STATUS_SUCCESS) return Status;

    REMOTE_HANDLE_INFO HandleInfo;
    HandleInfo.CurrentProcessId = CurrentProcessId;
    HandleInfo.hCurrentProcess = hCurrentProcess;

    PSYSTEM_HANDLE_INFORMATION_EX Handles = (PSYSTEM_HANDLE_INFORMATION_EX)MemBlock.Buffer;

    for (unsigned int i = 0; i < Handles->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Entry = &Handles->Handles[i];
        HandleInfo.ObjectType = Entry->ObjectTypeIndex;
        if ((Type == OB_TYPE_ALL) || (HandleInfo.ObjectType == (USHORT)Type)) {
            // Если хэндл открыт в нашем процессе - пропускаем:
            HandleInfo.RemoteProcessId = (ULONG)Entry->UniqueProcessId;

            // Если найденный хэндл в нашем процессе - пропускаем:
            if (SkipSelfHandles && (HandleInfo.RemoteProcessId == CurrentProcessId)) continue;

            // Открываем процесс, в котором открыт хэндл:
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, HandleInfo.RemoteProcessId);
            if (hProcess == NULL) continue;

            HANDLE hRemoteHandle = (HANDLE)Entry->HandleValue;
            
            // Копируем к себе хэндл с правами оригинала:
            BOOL Status = DuplicateHandle(hProcess, hRemoteHandle, hCurrentProcess, &HandleInfo.hObject, 0, FALSE, DUPLICATE_SAME_ACCESS);
            if (!Status) goto Continue;

            // Вызываем каллбэк:
            BOOL NeedToCloseSource = FALSE;
            HandleInfo.hRemoteProcess = hProcess;
            HandleInfo.GrantedAccess = Entry->GrantedAccess;
            HandleInfo.HandleAttributes = Entry->HandleAttributes;
            Callback(&HandleInfo, &NeedToCloseSource);
            
            // Если нужно закрыть оригинальный хэндл - закрываем:
            if (NeedToCloseSource) {
                CloseHandle(HandleInfo.hObject);
                Status = DuplicateHandle(hProcess, hRemoteHandle, hCurrentProcess, &HandleInfo.hObject, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
                if (!Status) goto Continue;
            }

            CloseHandle(HandleInfo.hObject);

Continue:
            CloseHandle(hProcess);
        }
    }

    return STATUS_SUCCESS;
}