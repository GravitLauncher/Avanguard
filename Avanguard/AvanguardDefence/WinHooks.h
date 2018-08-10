#pragma once

#include <Windows.h>
#include <vector>
#include <algorithm>

#include "PebTeb.h"
#include "ModulesUtils.h"

/*
    Принцип работы оконных хуков:
    1.	Ставим хук в инжектируемой библиотеке через
        SetWindowsHookEx
    2.	Атакуемое приложение получает сообщение
        через NtUserPeekMessage (user32.dll на Win7 и win32u.dll на Win10), 
        спускается в ядро (syscall)
    3.	Ядро вызывает юзермодный каллбэк с индексом в качестве аргумента
    4.	Аргумент - индекс функции __ClientLoadLibrary в PEB->KernelCallbacks 
    5.	Функция находится в user32.dll/win32u.dll и внутри вызывает LoadLibrary
*/

class WinHooks final {
private:
    static BOOL Initialized;
    static PVOID __ClientLoadLibrary;
    static std::vector<PVOID> KernelCallbacks;
    static BOOL Initialize();
public:
    static BOOL IsCalledFromWinHook();
};