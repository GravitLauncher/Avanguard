#pragma once

#include <Windows.h>

// #define USE_TLS_ENTRY

/*
    В TLS-каллбэке нельзя использовать CRT,
    прилинкованную статически (/MT), т.к. в
    этом случае CRT инициализируется в EntryPoint,
    который на момент вызова TLS-каллбэка ещё не вызван.

    Чтобы это обойти, из TLS-каллбэка передадим управление
    в EntryPoint, который инициализирует CRT и передаст
    управление в main(), откуда прыгнем обратно в TLS-каллбэк -
    таким образом, основное выполнение программы начнётся с TLS-каллбэка,
    а не с main().
*/

typedef VOID (__cdecl *_EntryPoint)();

#ifdef USE_TLS_ENTRY

extern HMODULE hInstance;
VOID WINAPI TlsCallback(HMODULE hModule, DWORD Reason, PCONTEXT Context);

#define Return2Tls() TlsCallback(hInstance, DLL_PROCESS_ATTACH, NULL)

#ifdef _WIN64
#pragma comment (linker, "/include:_tls_used")
#pragma comment (linker, "/include:_XLB")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK _XLB = (PIMAGE_TLS_CALLBACK)TlsCallback;
#pragma const_seg()
#else
#pragma comment (linker, "/include:__tls_used")
#pragma comment (linker, "/include:__XLB")
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK _XLB = (PIMAGE_TLS_CALLBACK)TlsCallback;
#pragma data_seg()
#endif

#endif