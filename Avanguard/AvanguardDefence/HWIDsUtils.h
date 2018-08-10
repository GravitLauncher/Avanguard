#pragma once

class HWIDs final {
public:
    static UINT64 GetCpuid();
    static UINT64 GetSmbiosId();
    static UINT64 GetMacId();
    static UINT64 GetHddId();
};