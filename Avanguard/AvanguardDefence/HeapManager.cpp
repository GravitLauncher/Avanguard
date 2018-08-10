#include "stdafx.h"
#include "HeapManager.h"

BOOL AllocReAllocFreeHeap(PHEAP_MEMBLOCK MemBlock, ULONG Size) {
    if (MemBlock == NULL) return FALSE;
    if (Size == 0) {
        if (MemBlock->Initialized) {
            HeapFree(GetProcessHeap(), 0, MemBlock->Buffer);
            ZeroMemory(MemBlock, sizeof(*MemBlock));
        }
        return TRUE;
    }

    if (MemBlock->Initialized && MemBlock->Size == Size) return TRUE;

    if (!MemBlock->Initialized || MemBlock->Buffer == NULL) {
        MemBlock->Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        if (MemBlock->Buffer == NULL) return FALSE;
        MemBlock->Size = Size;
        MemBlock->Initialized = TRUE;
        return TRUE;
    }

    PVOID ReallocatedBuffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MemBlock->Buffer, Size);
    if (!ReallocatedBuffer) return FALSE;

    MemBlock->Buffer = ReallocatedBuffer;
    MemBlock->Size = Size;
    MemBlock->Initialized = TRUE;

    return TRUE;
}