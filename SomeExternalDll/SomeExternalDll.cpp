#include "stdafx.h"

extern HMODULE hInstance;

HHOOK hHook = NULL;

LRESULT CALLBACK HookProc(int Code, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(hHook, Code, wParam, lParam);
}

VOID WINAPI HookEmAll() {
	if (hHook) return;
	hHook = SetWindowsHookEx(WH_DEBUG, HookProc, hInstance, 0);
}

VOID WINAPI UnHookEmAll() {
	if (hHook == NULL) return;
	if (UnhookWindowsHookEx(hHook)) hHook = NULL;
}