package ru.zaxar163;

public final class GuardBind {
    enum ThreatType {
        UNKNOWN_THREAT              (0),
        REMOTE_THREAD               (1),
        WINDOWS_HOOKS_INJECTION     (2),
        UNKNOWN_TRACE_LOAD_LIBRARY  (3),
        CONTEXT_MANIPULATION        (4),
        CRITICAL_MODULE_CHANGED     (5),
        UNKNOWN_INTERCEPTION        (6),
        UNKNOWN_MEMORY_REGION       (7),
        UNKNOWN_APC_DESTINATION     (8);

        private final int id;

        ThreatType(int value) {
            id = value;
        }

        public int getValue() { return id; }
        public static ThreatType getThreat(int threatType) {
            return ThreatType.values()[threatType];
        }
    }

    public interface ThreatNotifier {
        boolean call(int threatType);
    }

    static {
        System.load("Avanguard.dll");
    }

    public static native boolean    avnStartDefence();
    public static native void       avnStopDefence();
    public static native boolean    avnIsStarted();
    public static native boolean    avnIsStaticLoaded();
    public static native void       avnEliminateThreat(int threatType);
    public static native long       avnGetCpuid();
	public static native long       avnGetSmbiosId();
	public static native long       avnGetMacId();
	public static native long       avnGetHddId();
    public static native long       avnGetHash(byte[] data);
	public static native void       setCheckTime(int time);
	public static native int        getCheckTime();
	
    public static native void avnRegisterThreatNotifier(ThreatNotifier notifier);
}
