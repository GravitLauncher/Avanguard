#include "stdafx.h"
#include <Windows.h>
#include <WinTrust.h>
#include <Softpub.h>
//#include <wincrypt.h>
//#include <mscat.h>

#include "WinTrusted.h"

#include "xorstr/xorstr.hpp"

//#pragma comment(lib, "wintrust.lib")
//#pragma comment(lib, "crypt32.lib")

namespace {
    using _WinVerifyTrust = LONG(WINAPI*)(HWND hwnd, GUID* pgActionID, LPVOID pWVTData);
    _WinVerifyTrust __WinVerifyTrust = NULL;
}

BOOL InitWinTrust() {
    if (__WinVerifyTrust != NULL) return TRUE;
    HMODULE hWinTrust = GetModuleHandle(XORSTR(L"wintrust.dll"));
    if (!hWinTrust) hWinTrust = LoadLibrary(XORSTR(L"wintrust.dll"));
    if (hWinTrust) __WinVerifyTrust = reinterpret_cast<_WinVerifyTrust>(
        GetProcAddress(hWinTrust, XORSTR("WinVerifyTrust"))    
    );
    return __WinVerifyTrust != NULL;
}

BOOL IsFileSigned(LPCWSTR FilePath, BOOL CheckRevocation) {
    if (!InitWinTrust()) return FALSE;

    WINTRUST_FILE_INFO FileInfo = { 0 };
    FileInfo.cbStruct = sizeof(FileInfo);
    FileInfo.pcwszFilePath = FilePath;

    WINTRUST_DATA WinTrustData = { 0 };
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = CheckRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &FileInfo;

    GUID ActionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    return __WinVerifyTrust(NULL, &ActionGUID, &WinTrustData) == ERROR_SUCCESS;
}

/*
BOOL VerifyEmbeddedSignature(LPCWSTR FilePath) {
    WINTRUST_FILE_INFO FileInfo = { 0 };
    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileInfo.pcwszFilePath = FilePath;
    
    WINTRUST_DATA WinTrustData = { 0 };
    WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.pFile = &FileInfo;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID ActionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG Status = WinVerifyTrust(NULL, &ActionGUID, &WinTrustData);

    if (Status == ERROR_SUCCESS) return TRUE;

    // If it failed, try to verify using the catalog files:

    HANDLE hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    BYTE HashData[100];
    DWORD HashSize = sizeof(HashData);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &HashSize, HashData, 0)) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Create a string form of the hash (used later in MemberTag):
    LPWSTR MemberTag = new WCHAR[HashSize * 2 + 1];
    for (DWORD HashIterator = 0; HashIterator < HashSize; HashIterator++) {
        wsprintfW(&MemberTag[HashIterator * 2], L"%02X", HashData[HashIterator]);
    }

    HCATADMIN hCatAdmin;
    GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &DriverActionGuid, 0)) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Find the catalog which contains the hash:
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, HashData, HashSize, 0, NULL);
    if (hCatInfo) {
        CATALOG_INFO CatalogInfo = { 0 };
        CryptCATCatalogInfoFromContext(hCatInfo, &CatalogInfo, 0);

        WINTRUST_CATALOG_INFO WinTrustCatalogInfo = { 0 };
        WinTrustCatalogInfo.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        WinTrustCatalogInfo.pcwszCatalogFilePath = CatalogInfo.wszCatalogFile;
        WinTrustCatalogInfo.pcwszMemberFilePath = FilePath;
        WinTrustCatalogInfo.pcwszMemberTag = MemberTag;

        ZeroMemory(&WinTrustData, sizeof(WinTrustData));
        WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
        WinTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
        WinTrustData.pCatalog = &WinTrustCatalogInfo;
        WinTrustData.dwUIChoice = WTD_UI_NONE;
        WinTrustData.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
        
        Status = WinVerifyTrust(NULL, &ActionGUID, &WinTrustData);
            
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    delete[] MemberTag;
    CloseHandle(hFile);

    return Status == ERROR_SUCCESS;
}
*/