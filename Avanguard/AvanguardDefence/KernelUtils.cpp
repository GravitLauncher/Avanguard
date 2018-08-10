#include "stdafx.h"
#include "KernelUtils.h"

VOID ReplaceString(std::wstring &Text, const std::wstring &Source, const std::wstring &Destination) {
    for (size_t Index = 0; Index = Text.find(Source, Index), Index != std::wstring::npos;) {
        Text.replace(Index, Source.length(), Destination);
        Index += Destination.length();
    }
}

std::wstring GetSpecialFolderPath(ULONG SpecialFolder) {
    WCHAR LocalPath[MAX_PATH];
    BOOL Status = SUCCEEDED(SHGetFolderPath(0, SpecialFolder, 0, SHGFP_TYPE_CURRENT, (LPWSTR)&LocalPath[0]));
    return Status ? LocalPath : L"";
}

typedef BOOL(WINAPI *_EnumDeviceDrivers)(OUT PVOID* Buffer, IN DWORD BufferSize, OUT PDWORD BytesReturned);
typedef DWORD(WINAPI *_GetDeviceDriverFileName)(IN PVOID ImageBase, OUT LPTSTR FileName, IN DWORD Size);
_EnumDeviceDrivers       UniversalEnumDeviceDrivers = (_EnumDeviceDrivers)NULL;
_GetDeviceDriverFileName UniversalGetDeviceDriverFileName = (_GetDeviceDriverFileName)NULL;

BOOL InitK32DeviceDriverFunctions() {
    static BOOL IsK32Initialized = FALSE;
    if (IsK32Initialized) return TRUE;

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");

    UniversalEnumDeviceDrivers = (_EnumDeviceDrivers)GetProcAddress(hKernel32, "K32EnumDeviceDrivers");
    UniversalGetDeviceDriverFileName = (_GetDeviceDriverFileName)GetProcAddress(hKernel32, "K32GetDeviceDriverFileNameW");
    if ((UniversalEnumDeviceDrivers == NULL) || (UniversalGetDeviceDriverFileName == NULL)) {
        HMODULE hPsapi = GetModuleHandle(L"Psapi.dll");
        if (hPsapi == NULL) hPsapi = LoadLibrary(L"Psapi.dll");
        if (hPsapi == NULL) return FALSE;

        UniversalEnumDeviceDrivers = (_EnumDeviceDrivers)GetProcAddress(hPsapi, "EnumDeviceDrivers");
        UniversalGetDeviceDriverFileName = (_GetDeviceDriverFileName)GetProcAddress(hPsapi, "GetDeviceDriverFileNameW");
    }
    return IsK32Initialized = ((UniversalEnumDeviceDrivers != NULL) && (UniversalGetDeviceDriverFileName != NULL));
}

BOOL UEnumDeviceDrivers(OUT PVOID* Buffer, IN DWORD BufferSize, OUT PDWORD BytesReturned) {
    if (!InitK32DeviceDriverFunctions()) return FALSE;
    return UniversalEnumDeviceDrivers(Buffer, BufferSize, BytesReturned);
}

BOOL UGetDeviceDriverFileName(IN PVOID ImageBase, OUT LPTSTR FileName, IN DWORD Size) {
    if (!InitK32DeviceDriverFunctions()) return FALSE;
    return UniversalGetDeviceDriverFileName(ImageBase, FileName, Size);
}

BOOL GetKernelModulesList(DRIVERS_LIST& DriversList) {
    DriversList.clear();
    BOOL Status = FALSE;
    DRIVER_INFO DriverInfo;
    std::wstring WindowsPath = GetSpecialFolderPath(CSIDL_WINDOWS);

    DWORD RequiredBufferSize = 0;
    UEnumDeviceDrivers(NULL, 0, &RequiredBufferSize);

    PVOID* Buffer = (PVOID*)new BYTE[RequiredBufferSize];

    DWORD BytesReturned = 0;
    if (!UEnumDeviceDrivers(Buffer, RequiredBufferSize, &BytesReturned))
        goto Exit;

    // Перебираем все драйвера:
    WCHAR Path[MAX_PATH];
    ULONG DriversCount = BytesReturned / sizeof(PVOID);
    DriversList.reserve(DriversCount);
    for (unsigned int i = 0; i < DriversCount; i++) {
        DriverInfo.BaseAddress = Buffer[i];
        DriverInfo.Path = UGetDeviceDriverFileName(DriverInfo.BaseAddress, &Path[0], MAX_PATH) != 0
            ? Path
            : L"";
        ReplaceString(DriverInfo.Path, std::wstring(L"\\SystemRoot"), WindowsPath);
        DriversList.push_back(DriverInfo);
    }

Exit:
    delete[] Buffer;
    return Status;
}

PVOID GetKernelBaseAddress() {
    DWORD RequiredBufferSize = 0;
    UEnumDeviceDrivers(NULL, 0, &RequiredBufferSize);

    if (RequiredBufferSize == 0) return NULL;

    PVOID* Buffer = (PVOID*)new BYTE[RequiredBufferSize];

    DWORD BytesReturned = 0;

    if (!UEnumDeviceDrivers(Buffer, RequiredBufferSize, &BytesReturned)) {
        delete[] Buffer;
        return NULL;
    }

    PVOID KernelBaseAddress = BytesReturned > 0 ? Buffer[0] : NULL;
    delete[] Buffer;
    return KernelBaseAddress;
}

std::wstring GetKernelPath() {
    std::wstring WindowsPath = GetSpecialFolderPath(CSIDL_WINDOWS);
    std::wstring KernelPath = GetKernelModulePath(GetKernelBaseAddress());
    ReplaceString(KernelPath, std::wstring(L"\\SystemRoot"), WindowsPath);
    return KernelPath;
}

std::wstring GetKernelModulePath(PVOID BaseAddress) {
    if (BaseAddress == NULL) return L"";

    CONST DWORD CharactersCount = 256;
    WCHAR Buffer[CharactersCount];

    return 
        UGetDeviceDriverFileName(
            BaseAddress, 
            &Buffer[0], 
            CharactersCount
        ) 
        ? Buffer 
        : L"";
}