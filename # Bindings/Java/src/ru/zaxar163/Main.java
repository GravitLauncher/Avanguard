package ru.zaxar163;

public class Main {

    public static void main(String[] args) {
        GuardBind.avnRegisterThreatNotifier((int threatType) -> {
            System.out.println("Threat " + GuardBind.ThreatType.getThreat(threatType).name());
            return true;
        });

        GuardBind.avnEliminateThreat(GuardBind.ThreatType.UNKNOWN_APC_DESTINATION.getValue());

        GuardBind.avnRegisterThreatNotifier(null);
        GuardBind.avnEliminateThreat(GuardBind.ThreatType.UNKNOWN_APC_DESTINATION.getValue());
    }
}
