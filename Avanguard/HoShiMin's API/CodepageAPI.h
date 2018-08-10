#pragma once

#include <Windows.h>
#include <string>

std::string WideToAnsi32(const std::wstring &WideString, WORD CodePage = CP_ACP);
std::wstring AnsiToWide32(const std::string &AnsiString, WORD CodePage = CP_ACP);

std::string StrOemToAnsi(const std::string &String);
std::string StrAnsiToOem(const std::string &String);

VOID ConvertToAnsi(LPSTR OEM);
VOID ConvertToOem(LPSTR Ansi);