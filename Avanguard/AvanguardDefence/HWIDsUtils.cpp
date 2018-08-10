#include "stdafx.h"
#include "HWID.h"
#include "..\\t1ha\\t1ha.h"

#include <string>

#include "HWIDsUtils.h"

static void AddHwidEntry(std::string& Hwid, const char* Entry) {
    if (Entry) Hwid += (Entry);
}


UINT64 HWIDs::GetCpuid() {
    return GetCPUID();
}

UINT64 HWIDs::GetSmbiosId() {
    std::string Hwid;

    FIRMWARE_INFO Firmware = { 0 };
    if (!GetFirmwareInfo(&Firmware)) return 0;

    // Baseboard:
    AddHwidEntry(Hwid, Firmware.BaseboardData.AssetTag);
    AddHwidEntry(Hwid, Firmware.BaseboardData.LocationInChassis);
    AddHwidEntry(Hwid, Firmware.BaseboardData.Manufacturer);
    AddHwidEntry(Hwid, Firmware.BaseboardData.Product);
    AddHwidEntry(Hwid, Firmware.BaseboardData.SerialNumber);
    AddHwidEntry(Hwid, Firmware.BaseboardData.Version);

    // BIOS:
    AddHwidEntry(Hwid, Firmware.BIOSData.BIOSVersion);
    AddHwidEntry(Hwid, Firmware.BIOSData.ReleaseDate);
    AddHwidEntry(Hwid, Firmware.BIOSData.Vendor);

    // SystemInfo:
    AddHwidEntry(Hwid, Firmware.SystemData.Family);
    AddHwidEntry(Hwid, Firmware.SystemData.Manufacturer);
    AddHwidEntry(Hwid, Firmware.SystemData.ProductName);
    AddHwidEntry(Hwid, Firmware.SystemData.SerialNumber);
    AddHwidEntry(Hwid, Firmware.SystemData.SKUNumber);
    AddHwidEntry(Hwid, Firmware.SystemData.Version);

    FreeFirmwareInfo(&Firmware);

    return t1ha(Hwid.c_str(), Hwid.length(), 0x1EE7C0DEC0FFEE);
}

UINT64 HWIDs::GetMacId() {
    return GetMAC();
}

UINT64 HWIDs::GetHddId() {
    HDD_INFO HddInfo = { 0 };
    if (!GetHddInfo(0, &HddInfo)) return 0;
    constexpr UINT64 T1haSeed = 0x1EE7C0DEC0FFEE;
    UINT64 HddId = 0;
    if (HddInfo.VendorId) 
        HddId ^= t1ha(HddInfo.VendorId, strlen(HddInfo.VendorId), T1haSeed);
    if (HddInfo.ProductId)
        HddId ^= t1ha(HddInfo.ProductId, strlen(HddInfo.ProductId), T1haSeed);
    if (HddInfo.ProductRevision)
        HddId ^= t1ha(HddInfo.ProductRevision, strlen(HddInfo.ProductRevision), T1haSeed);
    if (HddInfo.SerialNumber)
        HddId ^= t1ha(HddInfo.SerialNumber, strlen(HddInfo.SerialNumber), T1haSeed);
    FreeHddInfo(&HddInfo);
    return HddId;
}