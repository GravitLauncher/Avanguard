#pragma once

#define _SCL_SECURE_NO_WARNINGS
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include <string>
#include <sstream>
#include <codecvt>
#include <algorithm>
#include <iomanip>

/*
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

* Simple - простой метод :
    Text = aFFabFFabc
        Source = ab
        Destination = abc

        Result = aFFabcFFabcc

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

* Selective - избирательный метод :
    Text = aFFabFFabc
        Source = ab
        Destination = abc

        Result = aFFabcFFabc - крайняя последовательность такая же, как
        заменяющая строка(abc), поэтому её не трогаем

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
*/

// Замена подстроки в строке; 
// возвращает true, если была хотя бы одна замена:
template<typename T>
bool SimpleReplaceString(T& Text, const T& Source, const T& Destination);

template<typename T>
bool SelectiveReplaceString(T& Text, const T& Source, const T& Destination);

typedef enum _REPLACING_METHOD {
    METHOD_SIMPLE,
    METHOD_SELECTIVE
} REPLACING_METHOD;

template<typename T>
T ReplaceString(
    const T& Text,
    const T& Source,
    const T& Destination,
    bool* WasReplaced,
    REPLACING_METHOD ReplacingMethod
);

std::string GetXMLParameter(const std::string &Data, const std::string &Parameter);

template <typename T>
inline std::string ValToAnsiStr(const T& Value) {
    std::ostringstream OutputStringStream;
    OutputStringStream << Value;
    return std::string(OutputStringStream.str());
}

template <typename T>
inline std::wstring ValToWideStr(const T& Value) {
    std::wostringstream OutputStringStream;
    OutputStringStream << Value;
    return std::wstring(OutputStringStream.str());
}

template <typename T>
inline std::string ValToAnsiHex(const T& Value, unsigned char Length, bool AddPrefix = true) {
    std::ostringstream OutputStringStream;
    if (AddPrefix)
        OutputStringStream << "0x" << std::uppercase << std::setfill('0') << std::setw(Length) << std::hex << Value;
    else
        OutputStringStream << std::uppercase << std::setfill('0') << std::setw(Length) << std::hex << Value;
    return std::string(OutputStringStream.str());
}

template <typename T>
inline std::wstring ValToWideHex(const T& Value, unsigned char Length, bool AddPrefix = true) {
    std::wostringstream OutputStringStream;
    if (AddPrefix)
        OutputStringStream << L"0x" << std::uppercase << std::setfill(L'0') << std::setw(Length) << std::hex << Value;
    else
        OutputStringStream << std::uppercase << std::setfill(L'0') << std::setw(Length) << std::hex << Value;
    return std::wstring(OutputStringStream.str());
}

template <typename T>
inline std::string FillLeftAnsi(const T& Value, unsigned char Length, char Filler) {
    std::ostringstream OutputStringStream;
    OutputStringStream << std::right << std::setfill(Filler) << std::setw(Length) << Value;
    return std::string(OutputStringStream.str());
}

template <typename T>
inline std::string FillRightAnsi(const T& Value, unsigned char Length, char Filler) {
    std::ostringstream OutputStringStream;
    OutputStringStream << std::left << std::setfill(Filler) << std::setw(Length) << Value;
    return std::string(OutputStringStream.str());
}

template <typename T>
inline std::wstring FillLeftWide(const T& Value, unsigned char Length, wchar_t Filler) {
    std::wostringstream OutputStringStream;
    OutputStringStream << std::right << std::setfill(Filler) << std::setw(Length) << Value;
    return std::wstring(OutputStringStream.str());
}

template <typename T>
inline std::wstring FillRightWide(const T& Value, unsigned char Length, wchar_t Filler) {
    std::wostringstream OutputStringStream;
    OutputStringStream << std::left << std::setfill(Filler) << std::setw(Length) << Value;
    return std::wstring(OutputStringStream.str());
}

template <typename T>
inline T StrToVal(const std::string& String) {
    std::istringstream InputStringStream(String);
    T Result;
    InputStringStream >> Result;
    return Result;
}


inline std::string WideToAnsi(const std::wstring& wide) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wide);
}

inline std::wstring AnsiToWide(const std::string& ansi) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(ansi);
}

template <typename T>
inline void LowerCaseRef(T& str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

template <typename T>
inline void UpperCaseRef(T& str) {
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

template <typename T>
inline T LowerCase(T str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

template <typename T>
inline T UpperCase(T str) {
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

template <typename T>
bool StartsWith(const T& value, const T& beginning) {
    return (beginning.size() <= value.size()) && std::equal(beginning.begin(), beginning.end(), value.begin());
}

template <typename T>
bool EndsWith(const T& value, const T& ending) {
    return (ending.size() <= value.size()) && std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

template<typename T>
T TrimLeft(const T& String, bool TrimTabs);

template<typename T>
T TrimRight(const T& String, bool TrimTabs);

template<typename T>
T Trim(const T& String, bool TrimTabs);

template <typename T>
T ExtractFileName(const T& path);

template <typename T>
T ExtractFilePath(const T& path);