#pragma once

#include <Windows.h>
#pragma warning(push)
#pragma warning(disable: 4005)
#include <winternl.h>
#include <ntstatus.h>
#pragma warning(pop)

#include "hModules.h"

#include "..\\HoShiMin's API\\HookHelper.h"

/* Системные определения */

typedef NTSTATUS (NTAPI *_LdrLoadDll) (
    IN PWCHAR			PathToFile,
    IN PULONG			Flags,
    IN PUNICODE_STRING	ModuleFileName,
    OUT PHANDLE			ModuleHandle
);

typedef NTSTATUS (NTAPI *_LdrUnloadDll) (
    IN HANDLE ModuleHandle
);

#define LDR_DLL_NOTIFICATION_REASON_LOADED		1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED	2

typedef struct _LDR_DLL_NOTIFICATION_DATA {
    ULONG Flags;					// Reserved.
    PCUNICODE_STRING FullDllName;	// The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;	// The base file name of the DLL module.
    PVOID DllBase;					// A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;				// The size of the DLL image, in bytes.
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION) (
    _In_		ULONG						NotificationReason,
    _In_		PLDR_DLL_NOTIFICATION_DATA	NotificationData,
    _In_opt_	PVOID						Context
);

typedef NTSTATUS (NTAPI *_LdrRegisterDllNotification) (
    _In_		ULONG							Flags,
    _In_		PLDR_DLL_NOTIFICATION_FUNCTION	NotificationFunction,
    _In_opt_	PVOID							Context,
    _Out_		PVOID							*Cookie
);

typedef NTSTATUS (NTAPI *_LdrUnregisterDllNotification) (
    _In_ PVOID Cookie
);

/* Пользовательские определения фильтров и каллбэков */

enum LDR_NOTIFICATION_REASON {
    LdrModuleLoaded = 1,
    LdrModuleUnloaded = 2
};

typedef VOID (CALLBACK *_DllNotificationRoutine) (
    LDR_NOTIFICATION_REASON Reason,
    IN PLDR_DLL_NOTIFICATION_DATA NotificationData,
    IN PCONTEXT Context
);

typedef NTSTATUS (CALLBACK *_PreLoadCallback) (
    OUT PBOOL			SkipOriginalCall,
    IN PWCHAR			PathToFile,
    IN PULONG			Flags,
    IN PUNICODE_STRING	ModuleFileName,
    OUT PHANDLE			ModuleHandle
);

typedef NTSTATUS (CALLBACK *_PostLoadCallback) (
    IN NTSTATUS			ReturnValue,
    IN PWCHAR			PathToFile,
    IN PULONG			Flags,
    IN PUNICODE_STRING	ModuleFileName,
    OUT PHANDLE			ModuleHandle
);

typedef NTSTATUS (CALLBACK *_PreUnloadCallback) (
    OUT PBOOL SkipOriginalCall,
    IN HANDLE ModuleHandle
);

typedef NTSTATUS (CALLBACK *_PostUnloadCallback) (
    IN NTSTATUS ReturnValue,
    IN HANDLE ModuleHandle
);

class ModulesFilter final {
private:
    // Состояние объекта:
    static BOOL Enabled;
    static BOOL Initialized;
    static HOOK_INFO HookInfo[2];
    static PVOID Cookie;

    static BOOL Initialize();

    // Оригинальные функции:
    static _LdrLoadDll LdrLoadDll, OrgnlLdrLoadDll;
    static _LdrUnloadDll LdrUnloadDll, OrgnlLdrUnloadDll;
    static _LdrRegisterDllNotification LdrRegisterDllNotification;
    static _LdrUnregisterDllNotification LdrUnregisterDllNotification;
    
    // Каллбэки:
    static _PreLoadCallback PreLoadCallback;
    static _PostLoadCallback PostLoadCallback;
    static _PreUnloadCallback PreUnloadCallback;
    static _PostUnloadCallback PostUnloadCallback;
    static _DllNotificationRoutine DllNotificationRoutine;

    // Функции-фильтры и нотификаторы:
    static NTSTATUS NTAPI HkdLdrLoadDll(
        IN PWCHAR			PathToFile,
        IN PULONG			Flags,
        IN PUNICODE_STRING	ModuleFileName,
        OUT PHANDLE			ModuleHandle
    );
    static NTSTATUS NTAPI HkdLdrUnloadDll(
        IN HANDLE ModuleHandle
    );
    static VOID CALLBACK LdrDllNotificationFunction(
        _In_		ULONG						NotificationReason,
        _In_		PLDR_DLL_NOTIFICATION_DATA	NotificationData,
        _In_opt_	PVOID						Context
    );
public:
    static BOOL EnableModulesFilter();
    static VOID DisableModulesFilter();
    static BOOL EnableDllNotification();
    static VOID DisableDllNotification();
    static VOID SetupFilterCallbacks(
        OPTIONAL _PreLoadCallback PreLoad = NULL,
        OPTIONAL _PostLoadCallback PostLoad = NULL,
        OPTIONAL _PreUnloadCallback PreUnload = NULL,
        OPTIONAL _PostUnloadCallback PostUnload = NULL
    );
    static VOID SetupNotificationCallbacks(
        OPTIONAL _DllNotificationRoutine Callback
    );
};