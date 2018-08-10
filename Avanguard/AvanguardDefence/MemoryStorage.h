#pragma once

#include <algorithm>
#include <concurrent_unordered_map.h>

#include "ProcessAPI.h"
#include "Locks.h"

#define PAGE_SIZE 4096
#define EXECUTABLE_MEMORY (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

class MemoryStorage {
private:
    concurrency::concurrent_unordered_map<PVOID, BOOL> MemoryMap; // BaseAddress -> Present
    void AddRegion(PVOID Address);
    void RemoveRegion(PVOID Address);
public:
    MemoryStorage();
    ~MemoryStorage();

    void ReloadMemoryRegions();

    void ProcessAllocation(PVOID Base);
    void ProcessFreeing(PVOID Base);
    bool IsMemoryInMap(PVOID Address);
};