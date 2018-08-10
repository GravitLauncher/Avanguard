#pragma once

#include <Windows.h>

class CSLock final {
private:
    CRITICAL_SECTION CriticalSection;
public:
    inline CSLock(ULONG SpinCount = 0xC0DE5AFE) {
        if (SpinCount)
            InitializeCriticalSectionAndSpinCount(&CriticalSection, SpinCount);
        else
            InitializeCriticalSection(&CriticalSection);
    }

    inline ~CSLock() { 
        DeleteCriticalSection(&CriticalSection); 
    }
    
    inline bool TryLock() {
        TryEnterCriticalSection(&CriticalSection);
    }

    inline void Lock() { 
        EnterCriticalSection(&CriticalSection); 
    }

    inline void Unlock() { 
        LeaveCriticalSection(&CriticalSection); 
    }
};