#include "stdafx.h"
#include "HWID.h"

BOOL GetHddInfo(BYTE PhysicalDriveNumber, OUT PHDD_INFO pHddInfo) {
    
    if (pHddInfo == NULL) return FALSE;
    ZeroMemory(pHddInfo, sizeof(HDD_INFO)); // Чистим выходную структуру

    // Имя девайса (жёсткого диска):
    WCHAR PhysicalDrivePath[48] = { 0 };
    swprintf_s(PhysicalDrivePath, L"\\\\.\\PhysicalDrive%d", PhysicalDriveNumber);

    // Открываем диск как файл для получения инфы:
    HANDLE hDrive = CreateFile(
        PhysicalDrivePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_DEVICE,
        NULL
    );

    if (hDrive == INVALID_HANDLE_VALUE) return FALSE;

    // Указываем, какую инфу хотим получить:
    STORAGE_PROPERTY_QUERY PropQuery;
    ZeroMemory(&PropQuery, sizeof(PropQuery));
    PropQuery.QueryType  = PropertyStandardQuery;
    PropQuery.PropertyId = StorageDeviceProperty;

    // Чистим дескриптор девайса:
    STORAGE_DEVICE_DESCRIPTOR DeviceDescriptor;
    ZeroMemory(&DeviceDescriptor, sizeof(DeviceDescriptor));

    DWORD BytesReturned = 0;

    // Вызываем, чтобы получить необходимый размер структуры:
    BOOL Status = DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &PropQuery,
        sizeof(PropQuery),
        &DeviceDescriptor,
        sizeof(DeviceDescriptor),
        &BytesReturned,
        NULL
    );

    if (!Status) goto Exit;

    // Вызываем с полным размером структуры:
    PSTORAGE_DEVICE_DESCRIPTOR pDeviceDescriptor = (PSTORAGE_DEVICE_DESCRIPTOR) new BYTE[DeviceDescriptor.Size];
    Status = DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &PropQuery,
        sizeof(PropQuery),
        pDeviceDescriptor,
        DeviceDescriptor.Size,
        &BytesReturned,
        NULL
    );

    if (!Status) {
        delete[] pDeviceDescriptor;
        goto Exit;
    }

    // Получили структуру, внутри которой по смещениям лежат строковые данные,
    // получаем указатели на них и возвращаем в структуре (саму структуру НЕ освобождаем!)

    ULONG VendorIdOffset        = pDeviceDescriptor->VendorIdOffset;
    ULONG ProductIdOffset       = pDeviceDescriptor->ProductIdOffset;
    ULONG ProductRevisionOffset = pDeviceDescriptor->ProductRevisionOffset;
    ULONG SerialNumberOffset    = pDeviceDescriptor->SerialNumberOffset;

    pHddInfo->VendorId = VendorIdOffset != 0 && VendorIdOffset < DeviceDescriptor.Size 
        ? (LPCSTR)pDeviceDescriptor + VendorIdOffset 
        : NULL;
    pHddInfo->ProductId = ProductIdOffset != 0 && ProductIdOffset < DeviceDescriptor.Size 
        ? (LPCSTR)pDeviceDescriptor + ProductIdOffset
        : NULL;
    pHddInfo->ProductRevision = ProductRevisionOffset != 0 && ProductRevisionOffset < DeviceDescriptor.Size 
        ? (LPCSTR)pDeviceDescriptor + ProductRevisionOffset
        : NULL;
    pHddInfo->SerialNumber = SerialNumberOffset	!= 0 && SerialNumberOffset < DeviceDescriptor.Size 
        ? (LPCSTR)pDeviceDescriptor + SerialNumberOffset
        : NULL;

    pHddInfo->HddInfoDataContainer = pDeviceDescriptor;

Exit:
    CloseHandle(hDrive);
    return Status;
}

VOID FreeHddInfo(IN OUT PHDD_INFO pHddInfo) {
    // Освобождаем структуру, полученную в GetHddInfo:
    if (pHddInfo == NULL) return;
    delete[] pHddInfo->HddInfoDataContainer;
    ZeroMemory(pHddInfo, sizeof(HDD_INFO));
}



// 24 бита:
typedef struct _CPUID {
    unsigned Vendor		: 1; // 0 = Intel, 1 = AMD
    unsigned BaseFamily	: 4;
    unsigned BaseModel	: 4;
    unsigned Stepping	: 4;
    unsigned BrandID	: 8;
    unsigned MMX		: 1;
    unsigned SSE1		: 1;
    unsigned SSE2		: 1;
    unsigned SSE3		: 1;
    unsigned SSSE3		: 1;
    unsigned SSE41		: 1;
    unsigned SSE42		: 1;
    unsigned RDTSCP		: 1;
    unsigned AVX		: 1;
    unsigned AES		: 1;
    unsigned FMA		: 1;
} CPUID, *PCPUID;

typedef struct _CPUID_INFO {
    DWORD EAX;
    DWORD EBX;
    DWORD ECX;
    DWORD EDX;
} CPUID_INFO, *PCPUID_INFO;

#define IsBitSet(Value, BitNumber)	((Value & (1 << BitNumber)) != 0)
#define Shr(Value, BitsCount)		(Value >> BitsCount)

/*
    Номера битов и вектора CPUID взяты из спецификаций:
    - AMD CPUID Specification
    - Intel(R) Processor Identification and the CPUID Instruction
*/
DWORD GetCPUID() {
    CPUID CPU = { 0 };
    CPUID_INFO CPUIDInfo = { 0 };

// Номера векторов CPUID:
#define CPUID_VENDOR	0x00000000
#define CPUID_FEATURES	0x00000001
#define CPUID_RDTSCP	0x80000001

// Хэши (XOR) вендоров (AuthenticAMD/GenuineIntel) - EBX ^ ECX ^ EDX:
#define INTEL_VENDOR_HASH	0x506E7F40
#define AMD_VENDOR_HASH		0x454D5A47

// Номера битов и смещения в регистрах CPUID_FEATURES (off* = offset, bn* = bit number):
// EAX:
#define offStepping 0 // [0..4]
#define offModel	4 // [0..4]	
#define offFamily	8 // [0..4]

// EBX:
#define offBrandID 0 // [0..7]

// ECX:
#define	bnSSE3	0
#define	bnSSSE3	9
#define	bnFMA	12
#define	bnSSE41	19
#define	bnSSE42	20
#define	bnAES	25
#define	bnAVX	28

// EDX:
#define	bnMMX	23
#define	bnSSE1	25
#define	bnSSE2	26

// Номера битов в регистрах CPUID_RDTSCP:
// EDX:
#define bnRDTSCP 27

    // Processor Vendor:
    __cpuid((int*)&CPUIDInfo, CPUID_VENDOR);
    DWORD VendorSignature = CPUIDInfo.EBX ^ CPUIDInfo.ECX ^ CPUIDInfo.EDX;
    switch (VendorSignature) {
    case INTEL_VENDOR_HASH	: CPU.Vendor = 0; break;
    case AMD_VENDOR_HASH	: CPU.Vendor = 1; break;
    }

    // CPU Features:
    __cpuid((int*)&CPUIDInfo, CPUID_FEATURES);
    CPU.BaseFamily	= Shr(CPUIDInfo.EAX, offFamily);
    CPU.BaseModel	= Shr(CPUIDInfo.EAX, offModel);
    CPU.Stepping	= Shr(CPUIDInfo.EAX, offStepping);

    CPU.BrandID = Shr(CPUIDInfo.EBX, offBrandID);

    CPU.SSE3	= IsBitSet(CPUIDInfo.ECX, bnSSE3);
    CPU.SSSE3	= IsBitSet(CPUIDInfo.ECX, bnSSSE3);
    CPU.FMA		= IsBitSet(CPUIDInfo.ECX, bnFMA);
    CPU.SSE41	= IsBitSet(CPUIDInfo.ECX, bnSSE41);
    CPU.SSE42	= IsBitSet(CPUIDInfo.ECX, bnSSE42);
    CPU.AES		= IsBitSet(CPUIDInfo.ECX, bnAES);
    CPU.AVX		= IsBitSet(CPUIDInfo.ECX, bnAVX);

    CPU.MMX		= IsBitSet(CPUIDInfo.EDX, bnMMX);
    CPU.SSE1	= IsBitSet(CPUIDInfo.EDX, bnSSE1);
    CPU.SSE2	= IsBitSet(CPUIDInfo.EDX, bnSSE2);

    // RDTSCP Support:
    __cpuid((int*)&CPUIDInfo, CPUID_RDTSCP);
    CPU.RDTSCP	= IsBitSet(CPUIDInfo.EDX, bnRDTSCP);

    return *(PDWORD)&CPU;
}


ULONGLONG GetMAC() {
    ULONGLONG MAC = 0;

    // Получаем размер буфера:
    ULONG AdaptersInfoSize = 0;
    DWORD Status = GetAdaptersInfo(NULL, &AdaptersInfoSize);
    if (Status != ERROR_BUFFER_OVERFLOW && AdaptersInfoSize == 0) return MAC;

    // Получаем инфу об адаптерах:
    PIP_ADAPTER_INFO AdapterInfo;
    AdapterInfo = (PIP_ADAPTER_INFO)malloc(AdaptersInfoSize);
    if (AdapterInfo == NULL) return MAC;
    Status = GetAdaptersInfo(AdapterInfo, &AdaptersInfoSize);
    if (Status != NO_ERROR) goto Exit;

    memcpy(&MAC, AdapterInfo->Address, AdapterInfo->AddressLength);

Exit:
    free(AdapterInfo);
    return MAC;
}

/*
    У каждой строковой инфы есть свой порядковый номер,
    последняя строка заканчивается двойным нуль-терминатором.
    Ищем строку по её порядковому номеру, который получаем из

*/
LPCSTR __fastcall FindStringByNumber(LPCSTR Base, BYTE StringNumber) {
    if (StringNumber <= 1) return Base;
    StringNumber--;
    for (int i = 0; i < StringNumber; i++) {
        Base = Base + strlen(Base) + 1;
    }
    return Base;
}

/*
    Переход на следующий блок относительно текущего:
    передаём произвольный адрес в текущем блоке текстовых данных 
    и отсчитываем до первых встреченных двух нуль-терминаторов:
*/
PVOID __fastcall GoToNextBlock(PVOID CurrentBlockEntireAddress) {
    PBYTE Address = (PBYTE)CurrentBlockEntireAddress;
    while (*(PWORD)Address != 0) Address++;
    return Address += 2;
}

// Вытаскиваем инфу о биосе:
PVOID ParseBIOSInfo(IN PBIOS_INFO BIOSInfo, OUT PFIRMWARE_INFO FirmwareInfo) {
    FirmwareInfo->BIOSData.BIOSInfo = BIOSInfo;

    LPCSTR BIOSTextData = (LPCSTR)BIOSInfo + BIOSInfo->Length;
    FirmwareInfo->BIOSData.Vendor		= FindStringByNumber(BIOSTextData, BIOSInfo->Vendor);
    FirmwareInfo->BIOSData.BIOSVersion	= FindStringByNumber(BIOSTextData, BIOSInfo->BIOSVersion);
    FirmwareInfo->BIOSData.ReleaseDate	= FindStringByNumber(BIOSTextData, BIOSInfo->BIOSReleaseDate);

    return GoToNextBlock((PVOID)BIOSTextData);
}

// Парсим системную инфу:
PVOID ParseSystemInfo(IN PSM_SYSTEM_INFO SystemInfo, OUT PFIRMWARE_INFO FirmwareInfo) {
    FirmwareInfo->SystemData.SystemInfo = SystemInfo;

    LPCSTR SystemInfoTextData = (LPCSTR)SystemInfo + SystemInfo->Length;
    FirmwareInfo->SystemData.Manufacturer	= FindStringByNumber(SystemInfoTextData, SystemInfo->Manufacturer);
    FirmwareInfo->SystemData.ProductName	= FindStringByNumber(SystemInfoTextData, SystemInfo->ProductName);
    FirmwareInfo->SystemData.Version		= FindStringByNumber(SystemInfoTextData, SystemInfo->Version);
    FirmwareInfo->SystemData.SerialNumber	= FindStringByNumber(SystemInfoTextData, SystemInfo->SerialNumber);
    FirmwareInfo->SystemData.SKUNumber		= FindStringByNumber(SystemInfoTextData, SystemInfo->SKUNumber);
    FirmwareInfo->SystemData.Family			= FindStringByNumber(SystemInfoTextData, SystemInfo->Family);

    return GoToNextBlock((PVOID)SystemInfoTextData);
}

// Парсим инфу о материнской плате:
PVOID ParseBoardInfo(IN PBASEBOARD_INFO BaseboardInfo, OUT PFIRMWARE_INFO FirmwareInfo) {
    FirmwareInfo->BaseboardData.BaseboardInfo = BaseboardInfo;

    LPCSTR BaseboardTextData = (LPCSTR)BaseboardInfo + BaseboardInfo->Length;
    FirmwareInfo->BaseboardData.Manufacturer		= FindStringByNumber(BaseboardTextData, BaseboardInfo->Manufacturer);
    FirmwareInfo->BaseboardData.Product				= FindStringByNumber(BaseboardTextData, BaseboardInfo->Product);
    FirmwareInfo->BaseboardData.Version				= FindStringByNumber(BaseboardTextData, BaseboardInfo->Version);
    FirmwareInfo->BaseboardData.SerialNumber		= FindStringByNumber(BaseboardTextData, BaseboardInfo->SerialNumber);
    FirmwareInfo->BaseboardData.AssetTag			= FindStringByNumber(BaseboardTextData, BaseboardInfo->AssetTag);
    FirmwareInfo->BaseboardData.LocationInChassis	= FindStringByNumber(BaseboardTextData, BaseboardInfo->LocationInChassis);

    return GoToNextBlock((PVOID)BaseboardTextData);
}

typedef UINT (WINAPI *_GetSystemFirmwareTable)(
    _In_ DWORD FirmwareTableProviderSignature,
    _In_ DWORD FirmwareTableID,
    _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableBuffer,
    _In_ DWORD BufferSize
);

_GetSystemFirmwareTable __GetSystemFirmwareTable = 
    (_GetSystemFirmwareTable)hModules::QueryAddress(hModules::hKernel32(), XORSTR("GetSystemFirmwareTable"));

BOOL GetFirmwareInfo(OUT PFIRMWARE_INFO FirmwareInfo) {
    if (FirmwareInfo == NULL) return FALSE;
    if (__GetSystemFirmwareTable == NULL) return FALSE;

    ZeroMemory(FirmwareInfo, sizeof(FIRMWARE_INFO));

    const DWORD ProviderSignature = 'RSMB'; // RawSMBIOS

    // Получаем размер:
    UINT RequiredSize = __GetSystemFirmwareTable(ProviderSignature, NULL, NULL, 0);
    if (RequiredSize == 0) return NULL;
    
    // Получаем Raw SMBIOS:
    PRAW_SMBIOS_DATA SMBIOS = (PRAW_SMBIOS_DATA) new BYTE[RequiredSize];
    UINT WrittenBytes = __GetSystemFirmwareTable(ProviderSignature, NULL, SMBIOS, RequiredSize);
    if (WrittenBytes > RequiredSize) {
        delete[] SMBIOS;
        return FALSE;
    }

    FirmwareInfo->RawSMBIOSData = SMBIOS;

// Номера блоков данных:
#define SIG_BIOS		0
#define SIG_SYSINFO		1
#define SIG_BASEBOARD	2

    // Обходим весь блок памяти и ищем структуры по их номерам:
    PVOID Address = SMBIOS->SMBIOSTableData;
    PVOID MaximumAddress = (PBYTE)Address + SMBIOS->Length;
    while (Address < MaximumAddress) {
        switch (*(PBYTE)Address) {
        case SIG_BIOS		: Address = ParseBIOSInfo((PBIOS_INFO)Address, FirmwareInfo); break;
        case SIG_SYSINFO	: Address = ParseSystemInfo((PSM_SYSTEM_INFO)Address, FirmwareInfo); break;
        case SIG_BASEBOARD	: Address = ParseBoardInfo((PBASEBOARD_INFO)Address, FirmwareInfo); break;
        default: Address = GoToNextBlock((PVOID)((PBYTE)Address + *((PBYTE)Address + 1)));
        }		
    }

    return TRUE;
}

VOID FreeFirmwareInfo(IN OUT PFIRMWARE_INFO FirmwareInfo) {
    // Освобождаем память, выделенную в GetFirmwareInfo:
    if (FirmwareInfo == NULL || FirmwareInfo->RawSMBIOSData == NULL) return;
    delete[] FirmwareInfo->RawSMBIOSData;
    ZeroMemory(FirmwareInfo, sizeof(FIRMWARE_INFO));
}

// Получить размер в байтах для переменной из реестра:
DWORD GetRegValueDataSize(HKEY hKey, LPWSTR ValueName, OUT OPTIONAL PDWORD ValueType) {
    DWORD Length = 0;
    DWORD Type = 0;
    if (RegQueryValueEx(hKey, ValueName, NULL, &Type, NULL, &Length) == ERROR_SUCCESS) {
        if (ValueType) *ValueType = Type;
        return Length;
    }
    return 0;
}

// Получить строковое значение из реестра:
LPWSTR GetRegValue(HKEY hKey, LPWSTR ValueName) {
    DWORD Type;
    DWORD ValueSize = GetRegValueDataSize(hKey, ValueName, NULL);
    if (ValueSize == 0) return NULL;
    LPWSTR Data = (LPWSTR) new BYTE[ValueSize];
    if (RegQueryValueEx(hKey, ValueName, NULL, &Type, (LPBYTE)Data, &ValueSize) == ERROR_SUCCESS) {
        return Data;
    } else {
        delete[] Data;
        return NULL;
    }
}

// Получаем информацию из реестра:
BOOL GetRegFirmwareInfo(OUT PREG_FIRMWARE_INFO RegFirmwareInfo) {
    if (RegFirmwareInfo == NULL) return FALSE;
    ZeroMemory(RegFirmwareInfo, sizeof(REG_FIRMWARE_INFO));

    HKEY hKey;
    const LPWSTR KeyPath = L"HARDWARE\\DESCRIPTION\\System\\BIOS"; // Ключ с инфой о биосе
    ULONG Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, KeyPath, NULL, KEY_READ | KEY_WOW64_64KEY, &hKey);

    if (Status != ERROR_SUCCESS) return FALSE;

    // Имена значений с информацией о биосе - аналог полей в структуре BIOS_INFO в SMBIOS:
    const LPWSTR BaseBoardProductValueName	= L"BaseBoardProduct";
    const LPWSTR BaseBoardRevisionValueName	= L"BaseBoardVersion";
    const LPWSTR BIOSReleaseDateValueName	= L"BIOSReleaseDate";
    const LPWSTR BIOSVendorValueName		= L"BIOSVendor";
    const LPWSTR BIOSVersionValueName		= L"BIOSVersion";

    RegFirmwareInfo->BaseboardProduct	= GetRegValue(hKey, BaseBoardProductValueName);
    RegFirmwareInfo->BaseboardVersion	= GetRegValue(hKey, BaseBoardRevisionValueName);
    RegFirmwareInfo->BIOSReleaseDate	= GetRegValue(hKey, BIOSReleaseDateValueName);
    RegFirmwareInfo->BIOSVendor			= GetRegValue(hKey, BIOSVendorValueName);
    RegFirmwareInfo->BIOSVersion		= GetRegValue(hKey, BIOSVersionValueName);

    RegCloseKey(hKey);
    return TRUE;
}

VOID FreeEntry(LPWSTR RegFirmwareInfoEntry) {
    // Освобождаем память, выделенную для строковой переменной из реестра:
    if (RegFirmwareInfoEntry) delete[] RegFirmwareInfoEntry;
}

// Освобождаем память, выделенную в GetRegFirmwareInfo:
VOID FreeRegFirmwareInfo(IN PREG_FIRMWARE_INFO RegFirmwareInfo) {
    FreeEntry(RegFirmwareInfo->BaseboardProduct);
    FreeEntry(RegFirmwareInfo->BaseboardVersion);
    FreeEntry(RegFirmwareInfo->BIOSReleaseDate);
    FreeEntry(RegFirmwareInfo->BIOSVendor);
    FreeEntry(RegFirmwareInfo->BIOSVersion);
}