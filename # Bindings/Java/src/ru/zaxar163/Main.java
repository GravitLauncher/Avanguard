package ru.avanguard;

public class Main {

    public static void main(String[] args) {
        AvnBind.avnRegisterThreatNotifier((int threatType) -> {
            System.out.println("Threat " + AvnBind.ThreatType.getThreat(threatType).name());
            return true;
        });

        AvnBind.avnEliminateThreat(AvnBind.ThreatType.UNKNOWN_APC_DESTINATION.getValue());

        AvnBind.avnRegisterThreatNotifier(null);
        AvnBind.avnEliminateThreat(AvnBind.ThreatType.UNKNOWN_APC_DESTINATION.getValue());
    }
}
