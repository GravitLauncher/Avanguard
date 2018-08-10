#include "stdafx.h"
#include "hModules.h"

HMODULE hModules::_hNtdll = NULL;
HMODULE hModules::_hKernelBase = NULL;
HMODULE hModules::_hKernel32 = NULL;
HMODULE hModules::_hProcess = NULL;
HMODULE hModules::_hCurrent = NULL; // Should to be initialized in DllMain
_GetProcAddress hModules::_XoredQueryAddress = NULL;