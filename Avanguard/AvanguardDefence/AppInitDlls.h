#pragma once

#include "hModules.h"
#include "..\\HoShiMin's API\\HookHelper.h"

class AppInitDlls final {
private:
    static BOOL Enabled;
    static BOOL Initialized;
    static HOOK_INFO HookInfo;
    static BOOL Initialize();
public:
    static BOOL DisableAppInitDlls();
    static VOID EnableAppInitDlls();
};