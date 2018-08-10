#include "stdafx.h"
#include "StringsAPI.h"

template<typename T>
bool SimpleReplaceString(T& Text, const T& Source, const T& Destination) {
    size_t SourceLength = Source.length();
    size_t DestinationLength = Destination.length();
    bool WasReplaced = false;

    for (size_t Index = 0; Index = Text.find(Source, Index), Index != T::npos;) {
        Text.replace(Index, SourceLength, Destination);
        Index += DestinationLength;
        WasReplaced = true;
    }

    return WasReplaced;
}

template<typename T>
bool SelectiveReplaceString(T& Text, const T& Source, const T& Destination) {
    size_t TextLength = Text.length();
    size_t SourceLength = Source.length();
    size_t DestinationLength = Destination.length();
    bool WasReplaced = false;

    T Environment;
    Environment.resize(DestinationLength);
    char* EnvironmentPtr = (char*)Environment.c_str();

    for (size_t Index = 0; Index = Text.find(Source, Index), Index != T::npos;) {
        if (DestinationLength <= TextLength - Index) {
            // Safe, but slower (require <iterator>):
            //Environment.clear();
            //std::copy(Text.begin() + Index, Text.begin() + Index + DestinationLength, std::back_inserter(Environment));
            
            // UNSAFE, but faster:
            Text.copy(EnvironmentPtr, DestinationLength, Index);
            
            if (Environment == Destination) {
                Index += DestinationLength;
                continue;
            }
        }
        Text.replace(Index, SourceLength, Destination);
        Index += DestinationLength;
        TextLength = Text.length();
        WasReplaced = true;
    }
    
    return WasReplaced;
};

template<typename T>
T ReplaceString(
    const T& Text,
    const T& Source,
    const T& Destination,
    bool* WasReplaced,
    REPLACING_METHOD ReplacingMethod
) {
    T Data(Text);

    bool _WasReplaced;

    switch (ReplacingMethod) {
    case METHOD_SIMPLE:
        _WasReplaced = SimpleReplaceString(Data, Source, Destination);
        break;
    case METHOD_SELECTIVE:
        _WasReplaced = SelectiveReplaceString(Data, Source, Destination);
        break;
    default:
        _WasReplaced = false;
    }

    if (WasReplaced) *WasReplaced = _WasReplaced;
    return Data;
}

std::string GetXMLParameter(const std::string& Data, const std::string& Parameter) {
    std::string StartParamBracket("<" + Parameter + ">");
    size_t StartPos = Data.find(StartParamBracket);
    if (StartPos != std::string::npos) {
        size_t EndPos = Data.find("</" + Parameter + ">", StartPos);
        if (EndPos != std::string::npos) {
            size_t ParamStartPosition = StartPos + StartParamBracket.length();
            size_t ParamSize = EndPos - ParamStartPosition;
            
            std::string Result;
            Result.resize(ParamSize);
            Data.copy((char*)Result.c_str(), ParamSize, ParamStartPosition);
            return Result;
        }
    }
    
    return std::string();
}

template<typename T>
T TrimLeft(const T& String, bool TrimTabs) {
    if (String.empty()) return String;
    
    int Length = String.length();
    
    if (TrimTabs) {
        for (int i = 0; i < Length; i++) {
            char Symbol = (char)String[i];
            if ((Symbol != ' ') && (Symbol != (char)0x09)) return String.substr(i);
        }
    } else {
        for (int i = 0; i < Length; i++) {
            if ((char)String[i] != ' ') return String.substr(i);
        }
    }

    return String;
}

template<typename T>
T TrimRight(const T& String, bool TrimTabs) {
    if (String.empty()) return String;

    int Length = String.length() - 1;

    if (TrimTabs) {
        for (int i = Length; i >= 0; i--) {
            char Symbol = (char)String[i];
            if ((Symbol != ' ') && (Symbol != (char)0x09)) return String.substr(0, i + 1);
        }
    } else {
        for (int i = Length; i >= 0; i--) {
            if ((char)String[i] != ' ') return String.substr(0, i + 1);
        }
    }

    return String;
}

template<typename T>
T Trim(const T& String, bool TrimTabs) {
    return TrimLeft(TrimRight(String, TrimTabs), TrimTabs);
}

template <typename T>
T _ExtractFileName(const T& path, size_t slash_pos, size_t backslash_pos) {
    size_t delim_pos;
    if ((backslash_pos != T::npos) && (slash_pos != T::npos)) {
        delim_pos = backslash_pos > slash_pos ? backslash_pos : slash_pos;
    } else {
        delim_pos = backslash_pos != T::npos ? backslash_pos : slash_pos;
    }

    if (delim_pos == T::npos) return path;

    delim_pos++;
    size_t remainder = path.length() - delim_pos;
    if (remainder == 0) return T();

    return path.c_str() + delim_pos;
}

template <>
std::string ExtractFileName<std::string>(const std::string& path) {
    size_t slash_pos = path.rfind("/");
    size_t backslash_pos = path.rfind("\\");
    return _ExtractFileName(path, slash_pos, backslash_pos);
}

template <>
std::wstring ExtractFileName<std::wstring>(const std::wstring& path) {
    size_t slash_pos = path.rfind(L"/");
    size_t backslash_pos = path.rfind(L"\\");
    return _ExtractFileName(path, slash_pos, backslash_pos);
}

template <typename T>
T _ExtractFilePath(const T& path, size_t slash_pos, size_t backslash_pos) {
    size_t delim_pos;
    if ((backslash_pos != T::npos) && (slash_pos != T::npos)) {
        delim_pos = backslash_pos > slash_pos ? backslash_pos : slash_pos;
    } else {
        delim_pos = backslash_pos != T::npos ? backslash_pos : slash_pos;
    }

    if (delim_pos == T::npos) return T();

    delim_pos++;
    size_t remainder = path.length() - delim_pos;
    if (remainder == 0) return T();

    T file_path;
    std::copy(path.begin(), path.begin() + delim_pos, std::back_inserter(file_path));
    return file_path;
}

template <>
std::string ExtractFilePath<std::string>(const std::string& path) {
    size_t slash_pos = path.rfind("/");
    size_t backslash_pos = path.rfind("\\");
    return _ExtractFilePath(path, slash_pos, backslash_pos);
}

template <>
std::wstring ExtractFilePath<std::wstring>(const std::wstring& path) {
    size_t slash_pos = path.rfind(L"/");
    size_t backslash_pos = path.rfind(L"\\");
    return _ExtractFilePath(path, slash_pos, backslash_pos);
}