#include "stdafx.h"
#include "CodepageAPI.h"

std::string WideToAnsi32(const std::wstring &WideString, WORD CodePage) {
    if (WideString.empty()) return std::string();

    int Length = WideCharToMultiByte(
        CodePage,
        WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR,
        WideString.c_str(),
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    if (Length == 0) return std::string();

    std::string Result;
    Result.resize(Length - 1);

    WideCharToMultiByte(
        CodePage,
        WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR,
        WideString.c_str(),
        -1,
        (LPSTR)Result.c_str(),
        Length - 1,
        NULL,
        NULL
    );

    return Result;
}

std::wstring AnsiToWide32(const std::string &AnsiString, WORD CodePage) {
    if (AnsiString.empty()) return std::wstring();

    int Length = MultiByteToWideChar(
        CodePage,
        MB_PRECOMPOSED,
        AnsiString.c_str(),
        -1,
        NULL,
        0
    );

    if (Length == 0) return std::wstring();

    std::wstring Result;
    Result.resize(Length - 1);

    MultiByteToWideChar(
        CodePage,
        MB_PRECOMPOSED,
        AnsiString.c_str(),
        -1,
        (LPWSTR)Result.c_str(),
        Length - 1
    );

    return Result;
}

std::string StrOemToAnsi(const std::string &String) {
    if (String.empty()) return std::string();

    unsigned int Length = (unsigned int)String.length();

    std::string Result;
    Result.resize(Length);

    OemToAnsiBuff(String.c_str(), (LPSTR)Result.c_str(), Length);
    return Result;
}

std::string StrAnsiToOem(const std::string &String) {
    if (String.empty()) return std::string();

    unsigned int Length = (unsigned int)String.length();

    std::string Result;
    Result.resize(Length);

    AnsiToOemBuff(String.c_str(), (LPSTR)Result.c_str(), Length);
    return Result;
}

VOID ConvertToAnsi(LPSTR OEM) {
    OemToAnsi((LPSTR)OEM, OEM);
}

VOID ConvertToOem(LPSTR Ansi) {
    AnsiToOem((LPSTR)Ansi, Ansi);
}