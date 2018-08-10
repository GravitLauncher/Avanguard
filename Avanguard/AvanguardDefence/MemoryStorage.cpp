#include "stdafx.h"
#include "MemoryStorage.h"

size_t inline AlignDown(size_t Value, size_t Factor) {
    return Value & ~(Factor - 1);
}

size_t inline AlignUp(size_t Value, size_t Factor) {
    return AlignDown(Value - 1, Factor) + Factor;
}

MemoryStorage::MemoryStorage() {
    ReloadMemoryRegions();
}

MemoryStorage::~MemoryStorage() {
    MemoryMap.clear();
}

void MemoryStorage::AddRegion(PVOID Address) {
    MEMORY_BASIC_INFORMATION MemoryInfo;
    QueryVirtualMemory(Address, &MemoryInfo);
    MemoryMap[MemoryInfo.AllocationBase] = TRUE;
}

void MemoryStorage::RemoveRegion(PVOID Address) {
    MEMORY_BASIC_INFORMATION MemoryInfo;
    QueryVirtualMemory(Address, &MemoryInfo);
    if (MemoryMap.find(MemoryInfo.AllocationBase) != MemoryMap.end())
        MemoryMap[MemoryInfo.AllocationBase] = FALSE;
}

void MemoryStorage::ReloadMemoryRegions() {
    MemoryMap.clear();
    EnumerateMemoryRegions(GetCurrentProcess(), [this](const PMEMORY_BASIC_INFORMATION Info) -> bool {
        if (Info->Protect & EXECUTABLE_MEMORY) 
            AddRegion(Info->BaseAddress);
        return true;
    });
}

void MemoryStorage::ProcessAllocation(PVOID Base) {
    AddRegion(Base);
}

void MemoryStorage::ProcessFreeing(PVOID Base) {
    RemoveRegion(Base);
}

bool MemoryStorage::IsMemoryInMap(PVOID Address) {
    MEMORY_BASIC_INFORMATION MemoryInfo;
    QueryVirtualMemory(Address, &MemoryInfo);
    return MemoryMap.find(MemoryInfo.AllocationBase) != MemoryMap.end();
}