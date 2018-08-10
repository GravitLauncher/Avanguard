#include "stdafx.h"
#include "AntiDebugging.h"

// Заколачиваем нули в PE-заголовок:
VOID ErasePEHeader(HMODULE hModule) {
    if (hModule == NULL) return;
#define PE_HEADER_SIZE 4 
    DWORD OldProtect;
    if (!VirtualProtect(hModule, PE_HEADER_SIZE, PAGE_READWRITE, &OldProtect)) return;
    ZeroMemory(hModule, PE_HEADER_SIZE);
    VirtualProtect(hModule, PE_HEADER_SIZE, OldProtect, &OldProtect);
}



VOID ChangeImageSize(HMODULE hModule, DWORD NewSize) {
    NTDEFINES::PPEB Peb = GetPEB(); // Получаем PEB
    NTDEFINES::PPEB_LDR_DATA PebLdrData = (NTDEFINES::PPEB_LDR_DATA)Peb->Ldr; // PEB->LDR_DATA - структура с инфой о модулях

    // Эта структура - двусвязный список, обходим его весь, пока не найдём наш модуль:
    NTDEFINES::PLDR_MODULE ListEntry = (NTDEFINES::PLDR_MODULE)PebLdrData->InLoadOrderModuleList.Flink;
    while (ListEntry && ListEntry->BaseAddress) {
        NTDEFINES::PLDR_MODULE LdrModule = (NTDEFINES::PLDR_MODULE)ListEntry;
        if (LdrModule->BaseAddress == hModule) { // Нашли наш модуль
            LdrModule->SizeOfImage = NewSize; // Выставляем новый размер модуля
            break;
        }
        ListEntry = (NTDEFINES::PLDR_MODULE)LdrModule->InLoadOrderModuleList.Flink;
    }
}

// Чистилка юникод-строк:
VOID DBG_CONVENTION FlushUnicodeString(PUNICODE_STRING UnicodeString) {
    UnicodeString->Buffer = NULL;
    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = 0;
}

VOID FlushLdrData() {
    // Получаем указатели на PEB и LDR_DATA:
    NTDEFINES::PPEB Peb = GetPEB();
    NTDEFINES::PPEB_LDR_DATA PebLdrData = (NTDEFINES::PPEB_LDR_DATA)Peb->Ldr;

    // Чистим командную строку и путь к главному модулю:
    FlushUnicodeString(&Peb->ProcessParameters->CommandLine);
    FlushUnicodeString(&Peb->ProcessParameters->ImagePathName);

    // Обходим двусвязный список модулей:
    NTDEFINES::PLDR_MODULE ListEntry = (NTDEFINES::PLDR_MODULE)PebLdrData->InLoadOrderModuleList.Flink;
    while (ListEntry && ListEntry->BaseAddress) {
        NTDEFINES::PLDR_MODULE LdrModule = ListEntry;

        // У каждого чистим заголовок:
        ErasePEHeader((HMODULE)LdrModule->BaseAddress);
        
        // Стираем размер модуля, точку входа и адрес загрузки:
        LdrModule->SizeOfImage = 0;
        LdrModule->BaseAddress = 0x00000000;
        LdrModule->EntryPoint = 0x00000000;

        // Стираем имена модулей:
        FlushUnicodeString(&LdrModule->BaseDllName);
        FlushUnicodeString(&LdrModule->FullDllName);
        
        // Идём на следующий элемент в списке:
        ListEntry = (NTDEFINES::PLDR_MODULE)ListEntry->InLoadOrderModuleList.Flink;
    }
}

VOID DestroyDbgUiRemoteBreakin() {
    PVOID DbgUiRemoteBreakin = hModules::QueryAddress(hModules::hNtdll(), XORSTR("DbgUiRemoteBreakin"));
    if (DbgUiRemoteBreakin) {
        DWORD OldProtect;
        VirtualProtect(DbgUiRemoteBreakin, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &OldProtect);
        *(PDWORD)DbgUiRemoteBreakin = 0x1EE7C0DE; // Ломаем функцию
        VirtualProtect(DbgUiRemoteBreakin, sizeof(DWORD), OldProtect, &OldProtect);
    }
}