#pragma once

#include <Windows.h>
#include <VersionHelpers.h>

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "PebTeb.h"
#include "..\\HoShiMin's API\\StringsAPI.h"

// VirtualLibName -> std::set<RealLibName>:
typedef std::unordered_set<std::wstring> REAL_LIBS_SET;
typedef std::unordered_map<std::wstring, REAL_LIBS_SET> VLIBS_MAP;

const VLIBS_MAP* GetVLibsMap();
bool ResolveDllName(const std::wstring& DllName, REAL_LIBS_SET& ResolvedNames);