#pragma once

#include <Windows.h>
#include <AclAPI.h>

#include <vector>

typedef enum _SID_OBJECT {
    sidCurrentUser,
    sidEveryone,
    sidSystem,
    sidAdministrators
} SID_OBJECT, *PSID_OBJECT;

typedef enum _SID_ACTION {
    Allow,
    Deny
} SID_ACTION, *PSID_ACTION;

typedef struct _DACL_CAPABILITY {
    PSID Sid;
    SID_ACTION SidAction;
    DWORD AccessRights;
} DACL_CAPABILITY, *PDACL_CAPABILITY;

class DACL {
private:
    HANDLE hObject;

    PTOKEN_USER TokenInfo = NULL;
    PSID SidCurrentUser, SidEveryone, SidSystem, SidAdministrators;
    std::vector<DACL_CAPABILITY> DACLs;

    PSID AllocCurrentUserSid();
    PSID AllocEveryoneSid();
    PSID AllocSystemSid();
    PSID AllocAdministratorsSid();

    PSID GetSid(SID_OBJECT SidObject);
public:
    DACL(HANDLE hObject);
    ~DACL();
    
    BOOL Allow(SID_OBJECT SidObject, ULONG AccessRights);
    BOOL Deny(SID_OBJECT SidObject, ULONG AccessRights);
    BOOL Apply();
};