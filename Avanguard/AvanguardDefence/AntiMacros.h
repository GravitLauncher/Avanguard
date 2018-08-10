#pragma once

#include <Windows.h>

enum HOOK_TYPE {
    HkKeyboard,
    HkMouse
};

enum HK_EVENT_RESULT {
    HkEventPass,
    HkEventCancel
};

typedef HK_EVENT_RESULT (CALLBACK *_HkFilterCallback)(
    int nCode,
    WPARAM wParam,
    LPARAM lParam // LPMSLLHOOKSTRUCT или LPKBDLLHOOKSTRUCT
);

class VirtualInput final {
private:
    static HHOOK hMouseHook;
    static HHOOK hKeyboardHook;
    static _HkFilterCallback OnVirtualMouseCallback;
    static _HkFilterCallback OnVirtualKeyboardCallback;
    static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPMSLLHOOKSTRUCT lParam);
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPKBDLLHOOKSTRUCT lParam);
public:
    // Если OnVirtualEventCallback == NULL, отменяет весь виртуальный ввод:
    static BOOL SetupFilter(HOOK_TYPE HookType, IN OPTIONAL _HkFilterCallback OnVirtualEventCallback = NULL);
    static BOOL RemoveFilter(HOOK_TYPE HookType);
};