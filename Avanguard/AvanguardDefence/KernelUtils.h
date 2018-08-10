#pragma once

#include <vector>
#include <string>
#include <ShlObj.h>
#include <Windows.h>

typedef struct _DRIVER_INFO {
    PVOID BaseAddress;
    std::wstring Path;
} DRIVER_INFO, *PDRIVER_INFO;

// Получить список загруженных драйверов и модулей ядра:
typedef std::vector<DRIVER_INFO> DRIVERS_LIST;
BOOL GetKernelModulesList(DRIVERS_LIST& DriversList);

// Получить базовый адрес загрузки ntoskrnl.exe:
PVOID GetKernelBaseAddress();

// Получить путь к файлу ntoskrnl.exe:
std::wstring GetKernelPath();

// Получить путь к модулю ядра по его адресу загрузки:
std::wstring GetKernelModulePath(PVOID BaseAddress);

// Динамически импортируемые функции из psapi.dll/kernel32.dll:
BOOL UEnumDeviceDrivers(OUT PVOID* Buffer, IN DWORD BufferSize, OUT PDWORD BytesReturned);
BOOL UGetDeviceDriverFileName(IN PVOID ImageBase, OUT LPTSTR FileName, IN DWORD Size);