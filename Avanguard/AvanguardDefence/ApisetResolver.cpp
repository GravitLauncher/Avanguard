#include "stdafx.h"
#include "ApisetResolver.h"

#pragma region APISET v2

typedef struct _API_SET_NAMESPACE2 {
    ULONG Version;
    ULONG Count;
    // API_SET_NAMESPACE_ENTRY Descriptor[0];
} API_SET_NAMESPACE2, *PAPI_SET_NAMESPACE2;

typedef struct _API_SET_NAMESPACE_ENTRY2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG RedirectorOffset;
} API_SET_NAMESPACE_ENTRY2, *PAPI_SET_NAMESPACE_ENTRY2;

typedef struct _API_SET_REDIRECTOR2 {
    ULONG NumberOfRedirections;
    // API_SET_VALUE_ENTRY Entries[0];
} API_SET_REDIRECTOR2, *PAPI_SET_REDIRECTOR2;

#pragma pack(push)
#pragma pack(4)
typedef struct _API_SET_VALUE_ENTRY2 {
    ULONG	NameOffset;
    USHORT	NameLength;
    ULONG	ValueOffset;
    USHORT	ValueLength;
} API_SET_VALUE_ENTRY2, *PAPI_SET_VALUE_ENTRY2;
#pragma pack(pop)

#pragma endregion

#pragma region APISET v4

typedef struct _API_SET_NAMESPACE4 {
    ULONG Version; 
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    // API_SET_NAMESPACE_ENTRY4 Array[0];
} API_SET_NAMESPACE4, *PAPI_SET_NAMESPACE4;

typedef struct _API_SET_NAMESPACE_ENTRY4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset; // Offset to API_SET_VALUE_ENTRY4
} API_SET_NAMESPACE_ENTRY4, *PAPI_SET_NAMESPACE_ENTRY4;

typedef struct _API_SET_VALUE_ENTRY4 {
    ULONG Flags;
    ULONG NumberOfRedirections;
    // API_SET_VALUE_ENTRY4 Array[0];
} API_SET_VALUE_ENTRY4, *PAPI_SET_VALUE_ENTRY4;

typedef struct _API_SET_VALUE_INFO4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_INFO4, *PAPI_SET_VALUE_INFO4;

#pragma endregion

#pragma region APISET v6

typedef struct _API_SET_NAMESPACE6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE6, *PAPI_SET_NAMESPACE6;

typedef struct _API_SET_HASH_ENTRY6 {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY6, *PAPI_SET_HASH_ENTRY6;

typedef struct _API_SET_NAMESPACE_ENTRY6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY6, *PAPI_SET_NAMESPACE_ENTRY6;

typedef struct _API_SET_VALUE_ENTRY6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY6, *PAPI_SET_VALUE_ENTRY6;

#pragma endregion

VLIBS_MAP* VLibsMap = NULL;

// PAPI_SET_NAMESPACE:
PVOID GetApiSetPtr() {
#ifdef _AMD64_
    return *(PVOID*)((PBYTE)GetPEB() + 0x68);
#else
    return *(PVOID*)((PBYTE)GetPEB() + 0x38);
#endif
}

void InsertVLib(const std::wstring& VLibName, const REAL_LIBS_SET& LibsSet) {
    const std::wstring DllPostfix(L".dll");
    const std::wstring ApiPrefix(L"api-");
    const std::wstring ExtPrefix(L"ext-");

    std::wstring NormalizedVLibName = LowerCase(VLibName);
    if (!EndsWith(NormalizedVLibName, DllPostfix)) NormalizedVLibName += DllPostfix;

    if (StartsWith(NormalizedVLibName, ApiPrefix) || StartsWith(NormalizedVLibName, ExtPrefix)) {
        VLibsMap->emplace(NormalizedVLibName, LibsSet);
        return;
    }

    VLibsMap->emplace(NormalizedVLibName, LibsSet);
    VLibsMap->emplace(ApiPrefix + NormalizedVLibName, LibsSet);
    VLibsMap->emplace(ExtPrefix + NormalizedVLibName, LibsSet);
}

void _FillApiSetMap2() {
    WCHAR Buffer[MAX_PATH];

    PAPI_SET_NAMESPACE2 ApiSetMap = (PAPI_SET_NAMESPACE2)GetApiSetPtr();
    PAPI_SET_NAMESPACE_ENTRY2 ApiSetNsEntry = (PAPI_SET_NAMESPACE_ENTRY2)((PBYTE)ApiSetMap + sizeof(*ApiSetMap));
    for (unsigned int i = 0; i < ApiSetMap->Count; i++) {
        RtlMoveMemory(Buffer, (LPWSTR)((PBYTE)ApiSetMap + ApiSetNsEntry->NameOffset), ApiSetNsEntry->NameLength);
        Buffer[ApiSetNsEntry->NameLength / sizeof(WCHAR)] = (WCHAR)0x0000;

        std::wstring VLibName(Buffer);

        REAL_LIBS_SET RealLibsSet;

        PAPI_SET_REDIRECTOR2 Redirector = (PAPI_SET_REDIRECTOR2)((PBYTE)ApiSetMap + ApiSetNsEntry->RedirectorOffset);
        PAPI_SET_VALUE_ENTRY2 Value = (PAPI_SET_VALUE_ENTRY2)((PBYTE)Redirector + sizeof(*Redirector));
        for (unsigned int j = 0; j < Redirector->NumberOfRedirections; j++) {
            if (Value->ValueOffset == 0 && Value->ValueLength == 0) {
                Value++;
                continue;
            }

            RtlMoveMemory(Buffer, (LPWSTR)((PBYTE)ApiSetMap + Value->ValueOffset), Value->ValueLength);
            Buffer[Value->ValueLength / sizeof(WCHAR)] = (WCHAR)0x0000;
            RealLibsSet.emplace(Buffer);
            Value++;
        }

        InsertVLib(VLibName, RealLibsSet);
        ApiSetNsEntry++;
    }
}

void _FillApiSetMap4() {
    WCHAR Buffer[MAX_PATH];

    PAPI_SET_NAMESPACE4 ApiSetMap = (PAPI_SET_NAMESPACE4)GetApiSetPtr();
    PAPI_SET_NAMESPACE_ENTRY4 ApiSetNsEntry = (PAPI_SET_NAMESPACE_ENTRY4)((PBYTE)ApiSetMap + sizeof(*ApiSetMap));
    for (unsigned int i = 0; i < ApiSetMap->Count; i++) {
        RtlMoveMemory(Buffer, (LPWSTR)((PBYTE)ApiSetMap + ApiSetNsEntry->NameOffset), ApiSetNsEntry->NameLength);
        Buffer[ApiSetNsEntry->NameLength / sizeof(WCHAR)] = (WCHAR)0x0000;

        std::wstring VLibName(Buffer);

        PAPI_SET_VALUE_ENTRY4 ValueEntry =
            (PAPI_SET_VALUE_ENTRY4)((PBYTE)ApiSetMap + ApiSetNsEntry->DataOffset);
        ULONG RedirectionsCount = ValueEntry->NumberOfRedirections;
        PAPI_SET_VALUE_INFO4 ValueInfo = (PAPI_SET_VALUE_INFO4)((PBYTE)ValueEntry + sizeof(*ValueEntry));

        REAL_LIBS_SET RealLibsSet;
        for (unsigned int j = 0; j < RedirectionsCount; j++) {
            if (ValueInfo->ValueOffset == 0 && ValueInfo->ValueLength == 0) {
                ValueInfo++;
                continue;
            }

            RtlMoveMemory(Buffer, ((PBYTE)ApiSetMap + ValueInfo->ValueOffset), ValueInfo->ValueLength);
            Buffer[ValueInfo->ValueLength / sizeof(WCHAR)] = (WCHAR)0x0000;

            RealLibsSet.emplace(Buffer);
            ValueInfo++;
        }

        InsertVLib(VLibName, RealLibsSet);
        ApiSetNsEntry++;
    }
}

void _FillApiSetMap6() {
    WCHAR Buffer[MAX_PATH];

    PAPI_SET_NAMESPACE6 ApiSetMap = (PAPI_SET_NAMESPACE6)GetApiSetPtr();
    PAPI_SET_NAMESPACE_ENTRY6 ApiSetNsEntry =
        (PAPI_SET_NAMESPACE_ENTRY6)((PBYTE)ApiSetMap + sizeof(*ApiSetMap));
    for (unsigned int i = 0; i < ApiSetMap->Count; i++) {
        RtlMoveMemory(Buffer, (LPWSTR)((PBYTE)ApiSetMap + ApiSetNsEntry->NameOffset), ApiSetNsEntry->NameLength);
        Buffer[ApiSetNsEntry->NameLength / sizeof(WCHAR)] = (WCHAR)0x0000;

        std::wstring VLibName(Buffer);

        ULONG RedirectionsCount = ApiSetNsEntry->ValueCount;
        PAPI_SET_VALUE_ENTRY6 ValueEntry =
            (PAPI_SET_VALUE_ENTRY6)((PBYTE)ApiSetMap + ApiSetNsEntry->ValueOffset);

        REAL_LIBS_SET RealLibsSet;
        for (unsigned int j = 0; j < RedirectionsCount; j++) {
            if (ValueEntry->ValueOffset == 0 && ValueEntry->ValueLength == 0) {
                ValueEntry++;
                continue;
            }
            
            RtlMoveMemory(Buffer, ((PBYTE)ApiSetMap + ValueEntry->ValueOffset), ValueEntry->ValueLength);
            Buffer[ValueEntry->ValueLength / sizeof(WCHAR)] = (WCHAR)0x0000;

            RealLibsSet.emplace(Buffer);
            ValueEntry++;
        }

        InsertVLib(VLibName, RealLibsSet);
        ApiSetNsEntry++;
    }
}

void FillApiSetMap() {
    if (VLibsMap == NULL)
        VLibsMap = new VLIBS_MAP();

    static bool Filled = false;
    if (Filled) return;

    if (!IsWindows7OrGreater()) {
        Filled = true;
        return;
    }

    ULONG Version = *(PULONG)GetApiSetPtr();
    switch (Version) {
    case 2:
        _FillApiSetMap2();
        break;
    case 4:
        _FillApiSetMap4();
        break;
    case 6:
        _FillApiSetMap6();
        break;
    default:
        std::exception("Unknown ApiSet version!");
    }

    Filled = true;
}

const VLIBS_MAP* GetVLibsMap() {
    FillApiSetMap();
    return VLibsMap;
}

bool ResolveDllName(const std::wstring& DllName, REAL_LIBS_SET& ResolvedNames) {
    std::wstring Name = ExtractFileName(DllName);
    LowerCaseRef(Name);

    ResolvedNames.clear();

    FillApiSetMap();
    
    const auto& Entry = VLibsMap->find(Name);
    bool Resolved = Entry != VLibsMap->end();
    if (Resolved) ResolvedNames = Entry->second;
    return Resolved;
}