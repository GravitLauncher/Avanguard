#pragma once

#include "PebTeb.h"
#include "PEAnalyzer.h"
#include "ModulesUtils.h"
#include "Locks.h"

#include "..\\t1ha\\t1ha.h"
#include "..\\HoShiMin's API\\StringsAPI.h"

#include <functional>

typedef struct _EXECUTABLE_SECTION_INFO {
    PVOID BaseAddress;
    ULONG Size;
} EXECUTABLE_SECTION_INFO, *PEXECUTABLE_SECTION_INFO;

typedef std::vector<EXECUTABLE_SECTION_INFO> EXEC_SECTIONS_SET;

typedef struct _MODULE_INFO {
    PVOID BaseAddress;
    EXEC_SECTIONS_SET ExecutableSections;
    std::wstring Name;
    UINT64 Checksum;
} MODULE_INFO, *PMODULE_INFO;


typedef std::function<bool(const MODULE_INFO& ModuleInfo)> OnChangedModuleCallback;

class ModulesStorage {
private:
    CSLock Locker;

    const std::wstring DllPostfix = std::wstring(L".dll");
    const std::wstring ExePostfix = std::wstring(L".exe");

    std::unordered_map<HMODULE, MODULE_INFO> LoadedModules;

    UINT64 CalculateChecksum(const EXEC_SECTIONS_SET& Sections);
    std::wstring GetNormalizedName(const std::wstring& Path);
    void AnalyzeExecutableSections(const PEAnalyzer& pe, MODULE_INFO& ModuleInfo);
public:
    ModulesStorage(BOOL CollectModulesInfo);
    ~ModulesStorage();

    BOOL IsCodeSectionsValid(HMODULE hModule);
    void RecalcModuleHash(HMODULE hModule);
    void RecalcModulesHashes();
    void FindChangedModules(OnChangedModuleCallback Callback);

    void FillModulesInfo();

    BOOL IsModuleInStorage(HMODULE hModule);

    void AddModule(HMODULE hModule);
    void RemoveModule(HMODULE hModule);

    void Lock();
    void Unlock();
};