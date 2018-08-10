#include "stdafx.h"
#include <Windows.h>
#include <Sfc.h>

#include "SfcWrapper.h"
#include "xorstr/xorstr.hpp"

BOOL Sfc::Initialized = FALSE;
_SfcIsFileProtected Sfc::__SfcIsFileProtected = NULL;

BOOL Sfc::Initialize() {
    if (Initialized) return TRUE;
    HMODULE hSfc = GetModuleHandle(XORSTR(L"sfc.dll"));
    if (!hSfc) hSfc = LoadLibrary(XORSTR(L"sfc.dll"));
    if (!hSfc) hSfc = LoadLibrary(XORSTR(L"sfc_os.dll"));
    if (hSfc) __SfcIsFileProtected = reinterpret_cast<_SfcIsFileProtected>(
        GetProcAddress(hSfc, XORSTR("SfcIsFileProtected"))
    );
    Initialized = TRUE;
    return __SfcIsFileProtected != NULL;
}

BOOL Sfc::IsFileProtected(LPCWSTR Path) {
    if (!Initialized) Initialize();
    return __SfcIsFileProtected ? __SfcIsFileProtected(NULL, Path) : FALSE;
}

