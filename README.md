# Avanguard
## The Win32 Anti-Intrusion Library  
### This library prevents some of injection techniques, debugging and static analyzing.  
Both x32 and x64 supports and includes:
* Static code encryptor
* Many anti-debugging techniques (WinAPI, NativeAPI, SEH, assembler and memory tricks)
* PE Analyzer
* Memory analyzer
* Call-stack analyzer
* Anti-injection techinques (against of CreateRemoteThread, manual modules mapping, injection through APC, windows hooks, AppInit_DLLs and context switching)
* Memory protection (kernel callbacks, modules remapping)
* Anti-splicing (modules executable sections and imports table verifying)
* Anti-macros (virtual keyboard and mouse input - useful for online games)
* Kernel modules info
* Threads and modules callbacks
* Handles keeper - prevents managing your app from other processes due to close handles of your process in external apps (for example, CheatEngine or another memory editors)
* Support of self-modified code
* TLS support
* DACLs support
* HWIDs collector
* Code-signing certificates and system files checkings
* API for external calls of defence functions

### Using
All you need is to load Avanguard.dll as soon as possible.  
It collects all information about consistence of process, sets up the memory, threads, APCs and modules filters and starts up the protection.  
  
You can use the AvnApi in C++ or any other native language using this code:  
```
#include "AvnApi.h"

HMODULE hAvn = GetModuleHandle(L"Avanguard.dll");
PAVN_API AvnApi = *(PAVN_API*)GetProcAddress(hAvn, "Stub");

AvnApi->Lock();
BOOL IsModuleValid = AvnApi->AvnIsModuleValid(hAvn);
// ... Other AvnApi calls ...
AvnApi->Unlock();
```
If you use the self-modification of modules in your code, you should use this snippet:
```
AvnApi->Lock();
// ... Module modification ...
AvnApi->AvnRehashModule(hChangedModule);
AvnApi->Unlock();
```
You should always use the _Lock()_/_Unlock()_ to AvnApi calls!  
  
Java bindings:
```
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
```
Note, that you shall not rename the package name!  
  
C# bindings:
```
using ...;
using AvnApi;

namespace AvnSample
{
    class Program
    {
        static void Main(string[] args)
        {
            AvnApi.AvnApi.Load(@"Avanguard.dll");
            AvnApi.AvnApi.API.AvnStart();
            while (true) ;
        }
    }
}
```