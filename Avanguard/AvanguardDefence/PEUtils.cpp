#include "stdafx.h"
#include "PEUtils.h"

// Информация о модуле,
// заполняется в CryptInitializeModuleInfo:
MODULE_INFO ModuleInfo = {
    NULL, NULL, { 0 }, 0xFFFFFFFF
};

// Получаем разницу между ImageBase и фактическим адресом загрузки:
ULONGLONG FASTCALL GetImageLoadDelta(HMODULE hModule) {
#define FILE_NAME_LEN 1024
    WCHAR FileName[FILE_NAME_LEN];
    DWORD FileNameSize = GetModuleFileName(hModule, FileName, FILE_NAME_LEN);

    HANDLE hFile = CreateFile(FileName, FILE_READ_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD FileSize = GetFileSize(hFile, NULL);
    PVOID Buffer = new BYTE[FileSize];
    ReadFile(hFile, Buffer, FileSize, &FileSize, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Buffer;
    if (DosHeader->e_magic != MZ_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)Buffer + DosHeader->e_lfanew);
    if (NtHeaders->Signature != PE_SIGNATURE) return 0;

    PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeaders->OptionalHeader;
    ULONGLONG ImageBase = OptionalHeader->ImageBase;

    delete[] Buffer;
    return (ULONGLONG)(hModule - ImageBase);
}

BOOL FASTCALL QueryModuleInfo(IN OUT PMODULE_INFO ModuleInfo) {
    HMODULE hModule = ModuleInfo->hModule;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (DosHeader->e_magic != MZ_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + DosHeader->e_lfanew);
    if (NtHeaders->Signature != PE_SIGNATURE) return FALSE;

    PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeaders->OptionalHeader;
    ModuleInfo->EntryPoint = (PBYTE)hModule + OptionalHeader->AddressOfEntryPoint;

#ifdef CODEPAGES_ARE_WRITEABLE
    // Ставим секциям права на запись:
    ULONG NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    for (unsigned int i = 0; i < NumberOfSections; i++, SectionHeader++) {
        PVOID SectionAddress = (PBYTE)hModule + SectionHeader->VirtualAddress;
        ULONG SectionSize = SectionHeader->Misc.VirtualSize;
        MEMORY_BASIC_INFORMATION MemoryInfo;
        ZeroMemory(&MemoryInfo, sizeof(MemoryInfo));
        if (VirtualQuery(SectionAddress, &MemoryInfo, sizeof(MemoryInfo))) {
            DWORD Protect = MemoryInfo.Protect;
            if ((Protect == PAGE_EXECUTE) || (Protect == PAGE_EXECUTE_READ)) {
                VirtualProtect(SectionAddress, SectionSize, PAGE_EXECUTE_READWRITE, &Protect);
            }
        }
    }
#endif

    PIMAGE_DATA_DIRECTORY RelocsDir = (PIMAGE_DATA_DIRECTORY)&OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD RelocsDirSize = RelocsDir->Size;

    PIMAGE_BASE_RELOCATION Relocs = (PIMAGE_BASE_RELOCATION)((PBYTE)hModule + RelocsDir->VirtualAddress);
    PIMAGE_BASE_RELOCATION FinalAddress = (PIMAGE_BASE_RELOCATION)((PBYTE)Relocs + RelocsDirSize);

    ModuleInfo->RelocsTableInfo.Size = RelocsDirSize;
    ModuleInfo->RelocsTableInfo.Relocs = Relocs;
    ModuleInfo->RelocsTableInfo.FinalAddress = FinalAddress;
    
    return TRUE;
}

// Инициализируем информацию о модуле:
VOID CryptInitializeModuleInfo(HMODULE hCurrentModule) {
    HMODULE hModule = hCurrentModule == NULL ? GetModuleHandle(NULL) : hCurrentModule;
    ModuleInfo.hModule = hModule;
    ModuleInfo.Delta = GetImageLoadDelta(ModuleInfo.hModule);
    QueryModuleInfo(&ModuleInfo);
}

#define PAGE_SIZE 4096
#define RELOCS_OFFSET_MASK 0b0000111111111111 /* Младшие 12 бит */ 

// Получаем список релоков для блока кода:
VOID FASTCALL FillRelocsSet(PCODE_BLOCK_INFO CodeBlockInfo, RELOCS_SET &RelocsSet) {
    RelocsSet.clear();
    
    PVOID Address	= CodeBlockInfo->Address;
    SIZE_T CodeSize	= CodeBlockInfo->Size;
    PVOID FinalCodeAddress = (PVOID)((PBYTE)Address + CodeSize);

    HMODULE hModule = ModuleInfo.hModule;

    PIMAGE_BASE_RELOCATION Relocs = ModuleInfo.RelocsTableInfo.Relocs;
    PIMAGE_BASE_RELOCATION FinalAddress = ModuleInfo.RelocsTableInfo.FinalAddress;

    // Идём по таблице релоков:
    while (Relocs < FinalAddress) {
        PDWORD RelocsBaseAddress = (PDWORD)((PBYTE)hModule + Relocs->VirtualAddress);
        if (RelocsBaseAddress >= FinalCodeAddress) break; // Если адрес релоков выше нашего блока - можем выходить

        DWORD RelocsCount = (Relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        // Попал ли наш адрес в страницу блока релоков:
        PBYTE RelocsFinalAddress = (PBYTE)RelocsBaseAddress + PAGE_SIZE;
        if (Address >= RelocsBaseAddress && Address < RelocsFinalAddress) {
            RelocsSet.reserve(RelocsCount - (RelocsSet.capacity() - RelocsSet.size()));
            PWORD RelocEntry = (PWORD)((PBYTE)Relocs + sizeof(IMAGE_BASE_RELOCATION));
            
            for (unsigned int i = 0; i < RelocsCount; i++, RelocEntry++) {
                PDWORD AddressToFix = (PDWORD)((PBYTE)RelocsBaseAddress + ((*RelocEntry) & RELOCS_OFFSET_MASK));

                // Если релок попадает в наш блок кода:
                if (AddressToFix >= Address && AddressToFix < FinalCodeAddress)
                    RelocsSet.push_back(AddressToFix);
            }
        }

        // На следующий блок релоков:
        Relocs = (PIMAGE_BASE_RELOCATION)((PBYTE)Relocs + Relocs->SizeOfBlock);
    }
}

#undef RELOCS_OFFSET_MASK
#undef PAGE_SIZE