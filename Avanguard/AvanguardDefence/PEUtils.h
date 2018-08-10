#pragma once

#include <Windows.h>
#include <winnt.h>
#include <vector>

#define CODEPAGES_ARE_WRITEABLE

#define MZ_SIGNATURE 0x5A4D // MZ
#define PE_SIGNATURE 0x4550 // PE

#define FASTCALL __fastcall

typedef struct _RELOCS_TABLE_INFO {
    PIMAGE_BASE_RELOCATION Relocs;
    PIMAGE_BASE_RELOCATION FinalAddress;
    DWORD Size;
} RELOCS_TABLE_INFO, *PRELOCS_TABLE_INFO;

typedef struct MODULE_INFO {
    HMODULE hModule; // Адрес загрузки текущего модуля
    PVOID EntryPoint; // Точка входа
    RELOCS_TABLE_INFO RelocsTableInfo; // Инфа о таблице релоков
    ULONGLONG Delta; // Разница между ImageBase и фактическим адресом загрузки
} MODULE_INFO, *PMODULE_INFO;

// Информация о модуле,
// заполняется в CryptInitializeModuleInfo:
extern MODULE_INFO ModuleInfo;

// Информация о шифруемом блоке кода:
typedef struct _CODE_BLOCK_INFO {
    PVOID	Address;
    SIZE_T	Size;
} CODE_BLOCK_INFO, *PCODE_BLOCK_INFO;

// Набор релоков для блока кода (НЕ для модуля):
typedef std::vector<PDWORD> RELOCS_SET;

VOID CryptInitializeModuleInfo(HMODULE hCurrentModule = NULL);
VOID FASTCALL FillRelocsSet(PCODE_BLOCK_INFO CodeBlockInfo, RELOCS_SET &RelocsSet);