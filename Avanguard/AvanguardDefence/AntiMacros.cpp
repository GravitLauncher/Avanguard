#include "stdafx.h"
#include "AntiMacros.h"

HHOOK VirtualInput::hMouseHook = NULL;
HHOOK VirtualInput::hKeyboardHook = NULL;
_HkFilterCallback VirtualInput::OnVirtualMouseCallback = NULL;
_HkFilterCallback VirtualInput::OnVirtualKeyboardCallback = NULL;

LRESULT CALLBACK VirtualInput::LowLevelMouseProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPMSLLHOOKSTRUCT lParam
) {
    return (nCode >= 0) && (lParam->flags & LLMHF_INJECTED) 
        ? (OnVirtualMouseCallback 
            ? (OnVirtualMouseCallback(nCode, wParam, (LPARAM)lParam) == HK_EVENT_RESULT::HkEventPass 
                ? CallNextHookEx(hMouseHook, nCode, wParam, (LPARAM)lParam) 
                : HK_EVENT_RESULT::HkEventCancel) 
            : HK_EVENT_RESULT::HkEventCancel)
        : CallNextHookEx(hMouseHook, nCode, wParam, (LPARAM)lParam);
}

LRESULT CALLBACK VirtualInput::LowLevelKeyboardProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPKBDLLHOOKSTRUCT lParam
) {
    return (nCode >= 0) && (lParam->flags & LLKHF_INJECTED)
        ? (OnVirtualKeyboardCallback
            ? (OnVirtualKeyboardCallback(nCode, wParam, (LPARAM)lParam) == HK_EVENT_RESULT::HkEventPass
                ? CallNextHookEx(hKeyboardHook, nCode, wParam, (LPARAM)lParam)
                : HK_EVENT_RESULT::HkEventCancel)
            : HK_EVENT_RESULT::HkEventCancel)
        : CallNextHookEx(hKeyboardHook, nCode, wParam, (LPARAM)lParam);
}

BOOL VirtualInput::SetupFilter(HOOK_TYPE HookType, IN OPTIONAL _HkFilterCallback OnVirtualEventCallback) {
    switch (HookType) {
    case HkKeyboard:
        OnVirtualKeyboardCallback = OnVirtualEventCallback;
        if (hKeyboardHook == NULL)
            hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, NULL, 0);
        return hKeyboardHook != NULL;

    case HkMouse:
        OnVirtualMouseCallback = OnVirtualEventCallback;
        if (hMouseHook == NULL)
            hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)LowLevelMouseProc, NULL, 0);
        return hMouseHook != NULL;

    default:
        return FALSE;
    }
}

BOOL VirtualInput::RemoveFilter(HOOK_TYPE HookType) {
    BOOL Status = TRUE;
    switch (HookType) {
    case HkKeyboard:
        if (hKeyboardHook) {
            Status = UnhookWindowsHookEx(hKeyboardHook);
            if (Status) hKeyboardHook = NULL;
        }
    case HkMouse:
        if (hMouseHook) {
            Status = UnhookWindowsHookEx(hMouseHook);
            if (Status) hMouseHook = NULL;
        }
        break;
    default:
        Status = FALSE;
    }
    return Status;
}