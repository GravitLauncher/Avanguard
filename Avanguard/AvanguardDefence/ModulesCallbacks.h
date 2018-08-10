#pragma once

#include "AvnDefinitions.h"
#include "PebTeb.h"
#include "ModulesFilter.h"
#include "ModulesStorage.h"
#include "MemoryCallbacks.h"
#include "WinHooks.h"

#include "..\\HoShiMin's API\\ColoredConsole.h"
#include "..\\HoShiMin's API\\DisasmHelper.h"

#include <set>
#include <vector>

extern ModulesStorage ValidModulesStorage;

NTSTATUS CALLBACK PreLoadModuleCallback(
    OUT PBOOL			SkipOriginalCall,
    IN PWCHAR			PathToFile,
    IN PULONG			Flags,
    IN PUNICODE_STRING	ModuleFileName,
    OUT PHANDLE			ModuleHandle
);

VOID CALLBACK DllNotificationRoutine(
    LDR_NOTIFICATION_REASON Reason,
    IN PLDR_DLL_NOTIFICATION_DATA NotificationData,
    IN PCONTEXT Context
);

// Вернуть FALSE для отмены загрузки модуля:
typedef BOOL(CALLBACK *_OnWindowsHookLoad)(PUNICODE_STRING ModuleFileName);
typedef BOOL(CALLBACK *_OnUnknownTraceLoad)(PVOID Address, PUNICODE_STRING ModuleFileName);

VOID SetupWindowsHooksFilter(_OnWindowsHookLoad Callback);
VOID SetupUnknownTraceLoadCallback(_OnUnknownTraceLoad Callback);