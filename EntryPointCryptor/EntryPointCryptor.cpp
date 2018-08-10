// EntryPointCryptor.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"

#include <locale>
#include <codecvt>
#include <string>

#include "PEAnalyzer.h"

typedef struct _MAPPING_INFO {
	HANDLE hFile;
	HANDLE hMapping;
	PVOID Memory;
	ULONG Size;
} MAPPING_INFO, *PMAPPING_INFO;

BOOL MapFile(IN LPWSTR Path, OUT PMAPPING_INFO Mapping) {
	if (Mapping == NULL) return FALSE;
	ZeroMemory(Mapping, sizeof(*Mapping));

	Mapping->hFile = CreateFile(
		Path, 
		GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL
	);

	if (Mapping->hFile == INVALID_HANDLE_VALUE) return NULL;

	Mapping->Size = GetFileSize(Mapping->hFile, NULL);
	Mapping->hMapping = CreateFileMapping(Mapping->hFile, NULL, PAGE_READWRITE, 0, Mapping->Size, NULL);
	if (Mapping->hMapping == NULL) goto CreateMappingError;

	Mapping->Memory = MapViewOfFile(Mapping->hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (Mapping->Memory == NULL) goto MappingError;

	return TRUE;

MappingError:
	CloseHandle(Mapping->hMapping);

CreateMappingError:
	CloseHandle(Mapping->hFile);
	ZeroMemory(Mapping, sizeof(*Mapping));
	return FALSE;
}

VOID UnmapFile(IN PMAPPING_INFO Mapping) {
	if (Mapping == NULL) return;
	if (Mapping->Memory) {
		FlushViewOfFile(Mapping->Memory, Mapping->Size);
		UnmapViewOfFile(Mapping->Memory);
	}
	if (Mapping->hMapping != NULL && Mapping->hMapping != INVALID_HANDLE_VALUE) CloseHandle(Mapping->hMapping);
	if (Mapping->hFile != NULL && Mapping->hFile != INVALID_HANDLE_VALUE) CloseHandle(Mapping->hFile);
	ZeroMemory(Mapping, sizeof(*Mapping));
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("Please, specify the file path!\r\n");
		return 0;
	}
	
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring path = converter.from_bytes(argv[1]);

	MAPPING_INFO MappingInfo = { 0 };
	if (!MapFile((LPWSTR)path.c_str(), &MappingInfo)) {
		printf("Unable to map file: %ws\r\n", path.c_str());
		return 0;
	}

	PEAnalyzer pe((HMODULE)MappingInfo.Memory, TRUE);

	SIZE_T EntryPointRva = (SIZE_T)pe.GetEntryPoint() - (SIZE_T)pe.GetImageBase();
	SIZE_T EntryPointRawOffset = pe.Rva2Offset(EntryPointRva);
	PULONGLONG EntryPoint = (PULONGLONG)((SIZE_T)MappingInfo.Memory + EntryPointRawOffset);
 	*EntryPoint ^= 0x1EE7C0DEC0FFEE;

	printf("Successfully XOR'ed!\r\n");

	UnmapFile(&MappingInfo);

    return 0;
}

