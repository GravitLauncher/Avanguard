#pragma once

#include "ThreatTypes.h"

VOID SetupNotificationRoutine(_AvnThreatNotifier ThreatCallback);

enum AVN_ET_ACTION {
    etContinue,
    etTerminate,
    etNotSpecified
};

VOID EliminateThreat(AVN_THREAT Threat, OPTIONAL PVOID Data, AVN_ET_ACTION Action);