#pragma once

#include <Windows.h>

typedef struct _HEAP_MEMBLOCK {
    PVOID Buffer;
    ULONG Size;
    BOOL Initialized;
} HEAP_MEMBLOCK, *PHEAP_MEMBLOCK;

BOOL AllocReAllocFreeHeap(PHEAP_MEMBLOCK MemBlock, ULONG Size);