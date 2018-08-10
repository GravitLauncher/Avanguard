#pragma once

#include <Windows.h>
#include <string>
#include <functional>

#include "PebTeb.h"

HMODULE GetModuleBase(PVOID Pointer);
std::wstring GetModuleName(PVOID AddressOrBase);
std::wstring GetModulePath(PVOID AddressOrBase);

typedef std::function<bool(NTDEFINES::PLDR_MODULE Module)> EnumerateModulesCallback;
void EnumerateModules(EnumerateModulesCallback Callback);