#pragma once

#include <winternl.h>
#include <intrin.h>

#include "hModules.h"
#include "..\\HoShiMin's API\\HookHelper.h"
#include "Locks.h"

#include <unordered_set>

/*
    LdrInitializeThunk - точка создания потока:
        x32:
         - EAX - процедура потока
         - EBX - аргумент
        x64:
         - RCX - процедура потока
         - RDX - аргумент
*/

// Каллбэк создания потока через CreateThread:
typedef VOID (CALLBACK *_ValidThreadCreatedCallback) (
    IN HANDLE ThreadId,
    IN PVOID EntryPoint,
    IN PVOID Parameter
);

// Каллбэк LdrInitializeThunk для всех потоков.
// Возвратить TRUE, если поток разрешить к исполнению,
// или FALSE, если поток необходимо завершить:
typedef BOOL (CALLBACK *_ThreadCreatedCallback) (
    PCONTEXT Context,
    BOOL ThreadIsLocal
);

BOOL SetupThreadsFilter(
    _ValidThreadCreatedCallback ValidThreadCreatedCallback,
    _ThreadCreatedCallback ThreadCreatedCallback
);

VOID RemoveThreadsFilter();