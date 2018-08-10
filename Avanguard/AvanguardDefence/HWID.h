#pragma once

#include <Windows.h>
#include <intrin.h>
#include <stdio.h>

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

// Структура информации о HDD:
typedef struct _HDD_INFO {
    LPCSTR	VendorId;
    LPCSTR	ProductId;
    LPCSTR	ProductRevision;
    LPCSTR	SerialNumber;
    PVOID	HddInfoDataContainer;	// Указатель на выделенный в GetHddInfo
                                    // блок памяти, где лежат VendorId,
                                    // ProductId, Revision и SN (все они указывают 
                                    // внутрь этого блока) - этот блок
                                    // освобождается в FreeHddInfo
} HDD_INFO, *PHDD_INFO;

BOOL GetHddInfo(BYTE PhysicalDriveNumber, OUT PHDD_INFO pHddInfo);
VOID FreeHddInfo(IN OUT PHDD_INFO pHddInfo);

DWORD GetCPUID();
ULONGLONG GetMAC();

#pragma warning(push)
#pragma warning(disable: 4200) // Отключаем предупреждение на массив нулевой длины
typedef struct _RAW_SMBIOS_DATA {
    BYTE	Used20CallingMethod;
    BYTE	SMBIOSMajorVersion;
    BYTE	SMBIOSMinorVersion;
    BYTE	DmiRevision;
    DWORD	Length;
    BYTE	SMBIOSTableData[];
} RAW_SMBIOS_DATA, *PRAW_SMBIOS_DATA;
#pragma warning(pop)

typedef ULONGLONG QWORD;

#pragma pack(push, 1) // Отключаем выравнивание
typedef struct _Type0 {
// SMBIOS 2.0+:
    BYTE	Type;
    BYTE	Length;
    WORD	Handle;
    BYTE	Vendor;
    BYTE	BIOSVersion;
    WORD	BIOSStartingAddressSegment;
    BYTE	BIOSReleaseDate;
    BYTE	BIOSROMSize;
    QWORD	BIOSCharacteristics;
// SMBIOS 2.4+:
    WORD	BIOSCharacteristicsExt;
    BYTE	SystemBIOSMajorRelease;
    BYTE	SystemBIOSMinorRelease;
    BYTE	EmbeddedControllerFirmwareMajorRelease;
    BYTE	EmbeddedControllerFirmwareMinorRelease;
// SMBIOS 3.1+:
    // WORD	ExtendedBIOSROMSize;
} BIOS_INFO, *PBIOS_INFO;


typedef struct _Type1 {
// SMBIOS 2.0+:
    BYTE	Type;
    BYTE	Length;
    WORD	Handle;
    BYTE	Manufacturer;
    BYTE	ProductName;
    BYTE	Version;
    BYTE	SerialNumber;
// SMBIOS 2.1+:
    BYTE	UUID[16];
    BYTE	WakeUpTime;
// SMBIOS 2.4+:
    BYTE	SKUNumber;
    BYTE	Family;
} SM_SYSTEM_INFO, *PSM_SYSTEM_INFO;

#pragma warning(push)
#pragma warning(disable: 4200)
typedef struct _Type2 {
    BYTE	Type;
    BYTE	Length;
    WORD	Handle;
    BYTE	Manufacturer;
    BYTE	Product;
    BYTE	Version;
    BYTE	SerialNumber;
    BYTE	AssetTag;
    BYTE	FeatureFlags;
    BYTE	LocationInChassis;
    WORD	ChassisHandle;
    BYTE	BoardType;
    BYTE	NumberOfContainedObjectHandles;
    WORD	ContainedObjectHandles[];
} BASEBOARD_INFO, *PBASEBOARD_INFO;
#pragma warning(pop)

typedef struct _Type3 {
    // To be done... когда-нибудь...
} MEMORY_DEVICE_INFO, *PMEMORY_DEVICE_INFO;
#pragma pack(pop)

// Дальше идут структуры сборной инфы из SMBIOS,
// все строковые переменные освобождаются в 
// FreeFirmwareInfo вместе с хранящим их блоком

// Инфа о BIOS'e:
typedef struct _BIOS_FIRMWARE_DATA {
    PBIOS_INFO BIOSInfo;
// SMBIOS 2.0+:
    LPCSTR Vendor;
    LPCSTR BIOSVersion;
    LPCSTR ReleaseDate;
} BIOS_FIRMWARE_DATA, *PBIOS_FIRMWARE_DATA;

// Сборная инфа о системе:
typedef struct _SYSTEM_FIRMWARE_DATA {
    PSM_SYSTEM_INFO SystemInfo;
// SMBIOS 2.0+:
    LPCSTR Manufacturer;
    LPCSTR ProductName;
    LPCSTR Version;
    LPCSTR SerialNumber;
// SMBIOS 2.4+:
    LPCSTR SKUNumber;
    LPCSTR Family;
} SYSTEM_FIRMWARE_DATA, *PSYSTEM_FIRMWARE_DATA;

// Информация о матплате:
typedef struct _BASEBOARD_FIRMWARE_DATA {
    PBASEBOARD_INFO BaseboardInfo;
    LPCSTR Manufacturer;
    LPCSTR Product;
    LPCSTR Version;
    LPCSTR SerialNumber;
    LPCSTR AssetTag;
    LPCSTR LocationInChassis;
} BASEBOARD_FIRMWARE_DATA, *PFIRMWARE_BASEBOARD_DATA;


// Основная структура, где собрано всё:
typedef struct _FIRMWARE_INFO {
    PRAW_SMBIOS_DATA		RawSMBIOSData;
    BIOS_FIRMWARE_DATA		BIOSData;
    SYSTEM_FIRMWARE_DATA	SystemData;
    BASEBOARD_FIRMWARE_DATA	BaseboardData;
} FIRMWARE_INFO, *PFIRMWARE_INFO;

BOOL GetFirmwareInfo(OUT PFIRMWARE_INFO FirmwareInfo);
VOID FreeFirmwareInfo(IN OUT PFIRMWARE_INFO FirmwareInfo);

// Дальше идут функции, читающие информацию из реестра вместо SMBIOS:

typedef struct _REG_FIRMWARE_INFO {
    LPWSTR BaseboardProduct;
    LPWSTR BaseboardVersion;
    LPWSTR BIOSReleaseDate;
    LPWSTR BIOSVendor;
    LPWSTR BIOSVersion;
} REG_FIRMWARE_INFO, *PREG_FIRMWARE_INFO;

BOOL GetRegFirmwareInfo(OUT PREG_FIRMWARE_INFO RegFirmwareInfo);
VOID FreeRegFirmwareInfo(IN PREG_FIRMWARE_INFO RegFirmwareInfo);