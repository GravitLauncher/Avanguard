using System;
using System.Runtime.InteropServices;

namespace AvnApi
{
    static class AvnApi
    {
        private const string k32LibName = @"kernel32.dll";

        [DllImport(k32LibName, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string libraryPath);

        [DllImport(k32LibName, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport(k32LibName, CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        private static T GetDelegate<T>(IntPtr pointer) where T : class
        {
            return Marshal.GetDelegateForFunctionPointer(pointer, typeof(T)) as T;
        }

        private static IntPtr GetPtr<T>(T method) where T : class
        {
            return Marshal.GetFunctionPointerForDelegate(method);
        }

        // Raw "Stub"-struct with pointers to AvnApi-functions:
        [StructLayout(LayoutKind.Sequential)]
        private struct AvnApiPointers
        {
            public IntPtr AvnStart;                   // Synchronized
            public IntPtr AvnStop;                    // Synchronized
            public IntPtr AvnIsStarted;               // Doesn't need synchronization
            public IntPtr AvnIsStaticLoaded;          // Doesn't need synchronization
            public IntPtr AvnRegisterThreatNotifier;  // Doesn't need synchronization
            public IntPtr AvnEliminateThreat;         // Doesn't need synchronization
            public IntPtr AvnLock;
            public IntPtr AvnUnlock;
            public IntPtr AvnRehashModule;
            public IntPtr AvnIsModuleValid;
            public IntPtr AvnIsFileProtected;
            public IntPtr AvnIsFileSigned;
            public IntPtr AvnVerifyEmbeddedSignature;
            public IntPtr AvnIsAddressAllowed;
            public IntPtr AvnGetCpuid;                 // Doesn't need synchronization
			public IntPtr AvnGetSmbiosId;              // Doesn't need synchronization
			public IntPtr AvnGetMacId;                 // Doesn't need synchronization
			public IntPtr AvnGetHddId;                 // Doesn't need synchronization
            public IntPtr AvnHash;                     // Doesn't need synchronization
        }

        public enum AVN_THREAT : byte
        {
            avnUnknownThreat,
            avnRemoteThread,
            avnWindowsHooksInjection,
            avnUnknownTraceLoadLibrary,
            avnContextManipulation,
            avnCriticalModuleChanged,
            avnUnknownInterception,
            avnUnknownMemoryRegion,
            avnUnknownApcDestination
        }

        public static class AvnApiDelegates
        {
            public delegate bool _AvnStart();
            public delegate void _AvnStop();
            public delegate bool _AvnIsStarted();
            public delegate bool _AvnIsStaticLoaded();
            public delegate void _AvnRegisterThreatNotifier(IntPtr callback);
            public delegate void _AvnEliminateThreat(AVN_THREAT avnThreat);
            public delegate void _AvnLock();
            public delegate void _AvnUnlock();
            public delegate void _AvnRehashModule(IntPtr hModule);
            public delegate bool _AvnIsModuleValid(IntPtr hModule);
            public delegate bool _AvnIsFileProtected([MarshalAs(UnmanagedType.LPWStr)] string filePath);
            public delegate bool _AvnIsFileSigned([MarshalAs(UnmanagedType.LPWStr)] string filePath, bool checkRevocation);
            public delegate bool _AvnVerifyEmbeddedSignature([MarshalAs(UnmanagedType.LPWStr)] string filePath);
            public delegate bool _AvnIsAddressAllowed(IntPtr address, bool includeJitMemory);
            public delegate UInt64 _AvnGetCpuid();
			public delegate UInt64 _AvnGetSmbiosId();
			public delegate UInt64 _AvnGetMacId();
			public delegate UInt64 _AvnGetHddId();
            public delegate UInt64 _AvnHash(IntPtr data, UInt32 size);
        }

        public class API
        {
            public static AvnApiDelegates._AvnStart AvnStart;
            public static AvnApiDelegates._AvnStop AvnStop;
            public static AvnApiDelegates._AvnIsStarted AvnIsStarted;
            public static AvnApiDelegates._AvnIsStaticLoaded AvnIsStaticLoaded;
            public static AvnApiDelegates._AvnRegisterThreatNotifier AvnRegisterThreatNotifier;
            public static AvnApiDelegates._AvnEliminateThreat AvnEliminateThreat;
            public static AvnApiDelegates._AvnLock AvnLock;
            public static AvnApiDelegates._AvnUnlock AvnUnlock;
            public static AvnApiDelegates._AvnRehashModule AvnRehashModule;
            public static AvnApiDelegates._AvnIsModuleValid AvnIsModuleValid;
            public static AvnApiDelegates._AvnIsFileProtected AvnIsFileProtected;
            public static AvnApiDelegates._AvnIsFileSigned AvnIsFileSigned;
            public static AvnApiDelegates._AvnVerifyEmbeddedSignature AvnVerifyEmbeddedSignature;
            public static AvnApiDelegates._AvnIsAddressAllowed AvnIsAddressAllowed;
            public static AvnApiDelegates._AvnGetCpuid AvnGetCpuid;
			public static AvnApiDelegates._AvnGetSmbiosId AvnGetSmbiosId;
			public static AvnApiDelegates._AvnGetMacId AvnGetMacId;
			public static AvnApiDelegates._AvnGetHddId AvnGetHddId;
            public static AvnApiDelegates._AvnHash AvnHash;
        }

        private static IntPtr hAvn = IntPtr.Zero;
        private static AvnApiPointers avnApiPointers;

        public static bool Load(string avnPath)
        {
            hAvn = LoadLibrary(avnPath);
            if (hAvn.Equals(IntPtr.Zero)) return false;

            IntPtr avnApiPtr = Marshal.ReadIntPtr(GetProcAddress(hAvn, "Stub"));
            avnApiPointers = Marshal.PtrToStructure<AvnApiPointers>(avnApiPtr);

            API.AvnStart = GetDelegate<AvnApiDelegates._AvnStart>(avnApiPointers.AvnStart);
            API.AvnStop  = GetDelegate<AvnApiDelegates._AvnStop>(avnApiPointers.AvnStop);
            API.AvnIsStarted = GetDelegate<AvnApiDelegates._AvnIsStarted>(avnApiPointers.AvnIsStarted);
            API.AvnIsStaticLoaded = GetDelegate<AvnApiDelegates._AvnIsStaticLoaded>(avnApiPointers.AvnIsStaticLoaded);
            API.AvnRegisterThreatNotifier = GetDelegate<AvnApiDelegates._AvnRegisterThreatNotifier>(avnApiPointers.AvnRegisterThreatNotifier);
            API.AvnEliminateThreat = GetDelegate<AvnApiDelegates._AvnEliminateThreat>(avnApiPointers.AvnEliminateThreat);
            API.AvnLock   = GetDelegate<AvnApiDelegates._AvnLock>(avnApiPointers.AvnLock);
            API.AvnUnlock = GetDelegate<AvnApiDelegates._AvnUnlock>(avnApiPointers.AvnUnlock);
            API.AvnRehashModule    = GetDelegate<AvnApiDelegates._AvnRehashModule>(avnApiPointers.AvnRehashModule);
            API.AvnIsModuleValid   = GetDelegate<AvnApiDelegates._AvnIsModuleValid>(avnApiPointers.AvnIsModuleValid);
            API.AvnIsFileProtected = GetDelegate<AvnApiDelegates._AvnIsFileProtected>(avnApiPointers.AvnIsFileProtected);
            API.AvnIsFileSigned    = GetDelegate<AvnApiDelegates._AvnIsFileSigned>(avnApiPointers.AvnIsFileSigned);
            API.AvnVerifyEmbeddedSignature  = GetDelegate<AvnApiDelegates._AvnVerifyEmbeddedSignature>(avnApiPointers.AvnVerifyEmbeddedSignature);
            API.AvnIsAddressAllowed = GetDelegate<AvnApiDelegates._AvnIsAddressAllowed>(avnApiPointers.AvnIsAddressAllowed);
            API.AvnGetCpuid    = GetDelegate<AvnApiDelegates._AvnGetCpuid>(avnApiPointers.AvnGetCpuid);
			API.AvnGetSmbiosId = GetDelegate<AvnApiDelegates._AvnGetSmbiosId>(avnApiPointers.AvnGetSmbiosId);
			API.AvnGetMacId    = GetDelegate<AvnApiDelegates._AvnGetMacId>(avnApiPointers.AvnGetMacId);
			API.AvnGetHddId    = GetDelegate<AvnApiDelegates._AvnGetHddId>(avnApiPointers.AvnGetHddId);
            API.AvnHash = GetDelegate<AvnApiDelegates._AvnHash>(avnApiPointers.AvnHash);

            return true;
        }

        public static bool Unload()
        {
            if (hAvn.Equals(IntPtr.Zero)) return true;
            if (avnApiPointers.AvnStop.Equals(IntPtr.Zero)) return true;
            return FreeLibrary(hAvn);
        }
    }
}
