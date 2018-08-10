unit AvnApi;

interface

type
  TAvnThreat = (
    avnUnknownThreat,
    avnRemoteThread,
    avnWindowsHooksInjection,
    avnUnknownTraceLoadLibrary,
    avnContextManipulation,
    avnCriticalModuleChanged,
    avnUnknownInterception,
    avnUnknownMemoryRegion,
    avnUnknownApcDestination
  );

  TAvnThreatNotifier = function(Threat: TAvnThreat; Data: Pointer): LongBool; stdcall;
  PAvnThreatNotifier = ^TAvnThreatNotifier;

  TAvnStart            = function: LongBool; stdcall;
  TAvnStop             = procedure; stdcall;
  TAvnIsStarted        = function: LongBool; stdcall;
  TAvnIsStaticLoaded   = function: LongBool; stdcall;
  TAvnRegisterThreatNotifier = procedure(Notifier: PAvnThreatNotifier); stdcall;
  TAvnEliminateThreat  = procedure(Threat: TAvnThreat; Data: Pointer); stdcall;
  TAvnLock             = procedure; stdcall;
  TAvnUnlock           = procedure; stdcall;
  TAvnRehashModule     = procedure(hModule: HMODULE); stdcall;
  TAvnIsModuleValid    = function(hModule: HMODULE): LongBool; stdcall;
  TAvnIsFileProtected  = function(FilePath: PWideChar): LongBool; stdcall;
  TAvnIsFileSigned     = function(FilePath: PWideChar; CheckRevocation: LongBool): LongBool; stdcall;
  TAvnVerifyEmbeddedSignature = function(FilePath: PWideChar): LongBool; stdcall;
  TAvnIsAddressAllowed = function(Address: Pointer; IncludeJitMemory: LongBool): LongBool; stdcall;
  TAvnGetCpuid         = function: UInt64; stdcall;
  TAvnGetSmbiosId      = function: UInt64; stdcall;
  TAvnGetMacId         = function: UInt64; stdcall;
  TAvnGetHddId         = function: UInt64; stdcall;
  TAvnHash             = function(Data: Pointer; Size: LongWord): LongBool; stdcall;

  TAvnApi = record
    AvnStart             : TAvnStart;
    AvnStop              : TAvnStop;
    AvnIsStarted         : TAvnIsStarted;
    AvnIsStaticLoaded    : TAvnIsStaticLoaded;
    AvnRegisterThreatNotifier: TAvnRegisterThreatNotifier;
    AvnEliminateThreat   : TAvnEliminateThreat;
    AvnLock              : TAvnLock;
    AvnUnlock            : TAvnUnlock;
    AvnRehashModule      : TAvnRehashModule;
    AvnIsModuleValid     : TAvnIsModuleValid;
    AvnIsFileProtected   : TAvnIsFileProtected;
    AvnIsFileSigned      : TAvnIsFileSigned;
    AvnVerifyEmbeddedSignature: TAvnVerifyEmbeddedSignature;
    AvnIsAddressAllowed  : TAvnIsAddressAllowed;
    AvnGetCpuid          : TAvnGetCpuid;
	AvnGetSmbiosId       : TAvnGetSmbiosId;
	AvnGetMacId          : TAvnGetMacId;
	AvnGetHddId          : TAvnGetHddId;
    AvnHash              : TAvnHash;
  end;
  PAvnApi = ^TAvnApi;
  PPAvnApi = ^PAvnApi;

implementation

end.
