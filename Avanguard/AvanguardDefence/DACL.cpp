#include "stdafx.h"
#include "DACL.h"

DACL::DACL(HANDLE hObject) {
    this->hObject = hObject;
    SidCurrentUser = AllocCurrentUserSid();
    SidEveryone = AllocEveryoneSid();
    SidSystem = AllocSystemSid();
    SidAdministrators = AllocAdministratorsSid();
}

DACL::~DACL() {
    if (TokenInfo) delete[] TokenInfo;
    if (SidEveryone) FreeSid(SidEveryone);
    if (SidSystem) FreeSid(SidSystem);
    if (SidAdministrators) FreeSid(SidAdministrators);
}



PSID DACL::AllocCurrentUserSid() {
    PSID Sid = NULL;
    BOOL Status = FALSE;

    HANDLE hToken;
    Status = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);
    if (!Status) goto Exit;

    // Получаем размер инфы токена:
    DWORD Size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &Size);
    if (!Size) goto Exit;

    // Выделяем память под инфу о токене:
    TokenInfo = (PTOKEN_USER)new BYTE[Size];
    if (TokenInfo == NULL) goto Exit;

    // Получаем инфу о токене:
    Status = GetTokenInformation(hToken, TokenUser, TokenInfo, Size, &Size);
    if (!Status) goto Exit;

    // Получаем SID текущего пользователя:
    Sid = TokenInfo->User.Sid;

Exit:
    CloseHandle(hToken);

    return Sid;
}

PSID DACL::AllocEveryoneSid() {
    PSID Sid = NULL;
    BOOL Status = FALSE;
    SID_IDENTIFIER_AUTHORITY SidIdentifier = SECURITY_WORLD_SID_AUTHORITY;
    Status = AllocateAndInitializeSid(&SidIdentifier, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Sid);
    return Status ? Sid : NULL;
}

PSID DACL::AllocSystemSid() {
    PSID Sid = NULL;
    BOOL Status = FALSE;
    SID_IDENTIFIER_AUTHORITY SidIdentifier = SECURITY_NT_AUTHORITY;
    Status = AllocateAndInitializeSid(&SidIdentifier, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &Sid);
    return Status ? Sid : NULL;
}

PSID DACL::AllocAdministratorsSid() {
    PSID Sid = NULL;
    BOOL Status = FALSE;
    SID_IDENTIFIER_AUTHORITY SidIdentifier = SECURITY_NT_AUTHORITY;
    Status = AllocateAndInitializeSid(&SidIdentifier, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Sid);
    return Status ? Sid : NULL;
}

PSID DACL::GetSid(SID_OBJECT SidObject) {
    switch (SidObject) {
    case sidCurrentUser: return SidCurrentUser;
    case sidEveryone: return SidEveryone;
    case sidSystem: return SidSystem;
    case sidAdministrators: return SidAdministrators;
    default: return FALSE;
    }
}



BOOL DACL::Allow(SID_OBJECT SidObject, ULONG AccessRights) {
    PSID Sid = GetSid(SidObject);
    if (Sid == NULL) return FALSE;

    DACL_CAPABILITY Capability;
    Capability.Sid = Sid;
    Capability.SidAction = SID_ACTION::Allow;
    Capability.AccessRights = AccessRights;
    DACLs.emplace_back(Capability);
    return TRUE;
}

BOOL DACL::Deny(SID_OBJECT SidObject, ULONG AccessRights) {
    PSID Sid = GetSid(SidObject);
    if (Sid == NULL) return FALSE;

    DACL_CAPABILITY Capability;
    Capability.Sid = Sid;
    Capability.SidAction = SID_ACTION::Deny;
    Capability.AccessRights = AccessRights;
    DACLs.emplace_back(Capability);
    return TRUE;
}

BOOL DACL::Apply() {
    // Рассчитываем суммарный размер ACL:
    DWORD AclSize = sizeof(ACL);
    for (const auto& Capability : DACLs) {
        AclSize += GetLengthSid(Capability.Sid) - sizeof(DWORD);
        switch (Capability.SidAction) {
        case SID_ACTION::Allow:
            AclSize += sizeof(ACCESS_ALLOWED_ACE);
            break;
        case SID_ACTION::Deny:
            AclSize += sizeof(ACCESS_DENIED_ACE);
            break;
        }
    }

    BOOL Status = FALSE;

    // Выделяем память под DACL:
    PACL Dacl = (PACL)new BYTE[AclSize];
    if (Dacl == NULL) return Status;

    // Инициализируем DACL:
    Status = InitializeAcl(Dacl, AclSize, ACL_REVISION);
    if (!Status) goto Exit;

    // Устанавливаем правила:
    for (const auto& Capability : DACLs) {
        switch (Capability.SidAction) {
        case SID_ACTION::Allow:
            Status = AddAccessAllowedAce(Dacl, ACL_REVISION, Capability.AccessRights, Capability.Sid);
            break;
        case SID_ACTION::Deny:
            Status = AddAccessDeniedAce(Dacl, ACL_REVISION, Capability.AccessRights, Capability.Sid);
            break;
        default:
            Status = FALSE;
        }
        if (!Status) goto Exit;
    }

    // Создаём SECURITY_DESCRIPTOR:
    SECURITY_DESCRIPTOR SecurityDescriptor;
    Status = InitializeSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!Status) goto Exit;

    Status = SetSecurityDescriptorDacl(&SecurityDescriptor, TRUE, Dacl, FALSE);
    if (!Status) goto Exit;

    // Устанавливаем SECURITY_DESCRIPTOR:
    DWORD Result = SetSecurityInfo(
        hObject,
        SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        SidCurrentUser,
        NULL,
        Dacl,
        NULL
    );
    Status = Result == ERROR_SUCCESS;

Exit:
    delete[] Dacl;
    return Status;
}