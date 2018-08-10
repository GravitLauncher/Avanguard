#include "stdafx.h"

HMODULE hInstance;

BOOL APIENTRY DllMain(
	HMODULE		hModule,
	DWORD		dwReason,
	PCONTEXT	lpContext
) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		hInstance = hModule;
	}

	return TRUE;
}