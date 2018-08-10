#pragma once

#include <winternl.h>
#include <processthreadsapi.h>
#include <VersionHelpers.h>

#include "hModules.h"

typedef BOOL (WINAPI *_SetThreadInformation)(
    HANDLE hThread,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    LPVOID ThreadInformation,
    DWORD ThreadInformationSize
);

typedef BOOL (WINAPI *_SetProcessMitigationPolicy)(
    PROCESS_MITIGATION_POLICY	MitigationPolicy,
    PVOID						lpBuffer,
    SIZE_T						dwLength
);

class Mitigations final {
private:
    static BOOL Initialized;
    static _SetThreadInformation __SetThreadInformation;
    static _SetProcessMitigationPolicy __SetProcessMitigationPolicy;
    static BOOL Initialize();
public:
    static BOOL SetProhibitDynamicCode(BOOL AllowThreadsOptOut);
    static BOOL SetThreadAllowedDynamicCode();
};