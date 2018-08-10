#pragma once

#include "PebTeb.h"
#include <intrin.h>

// https://wasm.in/threads/antiotladochnye-trjuki.15571/

#pragma comment(lib, "ntdll.lib")

/*
    Функции очистки PE-заголовков: при подключении к процессу отладчик
    попытается распарсить структуры PEB (Process Environment Block) и
    TEB (Thread Env. Block), где хранится вся информация о процессе
    на момент его создания: командная строка, список модулей и много что
    ещё - большая часть из той информации, что в ядре хранится
    в структуре EPROCESS. Если стереть информацию об адресах загрузки
    модулей из LDR-структур - отладчик не сможет понять, где точка входа.

    Определения PEB:
    - Из проекта ReactOS: https://doxygen.reactos.org/d0/d53/struct__PEB.html
    - Из Process Hacker'a: http://processhacker.sourceforge.net/doc/struct___p_e_b32.html

    Получить PEB:
    PPEB Peb32 = (PPEB)__readfsdword(0x30); // Для 32х-битных процессов (в 64х-битных Windows у Wow64-прцессов есть и Peb32, и Peb64)
    PPEB Peb64 = (PPEB)__readgsqword(0x60); // Для 64х-битных процессов

    Статья на хабре: https://habrahabr.ru/post/187226/
    Инфа из вики: https://en.wikipedia.org/wiki/Process_Environment_Block

    ErasePEHeader - стирает заголовок у выбранного модуля (использовать можно)
    FlushLdrFata - то же, что и ErasePEHeader, только для ВСЕХ модулей (использовать НЕЛЬЗЯ, т.к. ломается программа)
    ChangeImageSize - изменяет размер образа в заголовке, вводит в ступор многие отладчики
*/
VOID ErasePEHeader(HMODULE hModule);
VOID FlushLdrData();
VOID ChangeImageSize(HMODULE hModule, DWORD NewSize);

/*
    При подключении отладчика в отлаживаемом процессе вызывается
    функция DbgUiRemoteBreakin (ntdll.dll). Испортив её, мы сломаем процесс
    при попытке подключения к нему отладчика. По адресу функции
    записываю 4 байта 0x1EE7C0DE
*/
VOID DestroyDbgUiRemoteBreakin();

// С таким соглашением у нас будут работать функции антиотладки: 
// встраиваемые, и для скорости аргументы (если есть) идут в регистрах
#define DBG_CONVENTION __forceinline __fastcall

/*
    Эти два трюка основаны на результате функций IsDebuggerPresent и
    CheckRemoteDebuggerPresent (kernel32.dll) - возвращают TRUE/FALSE
    в зависимости от того, присоединён ли отладчик к нашему процессу
*/
BOOL DBG_CONVENTION CheckRDP();
BOOL DBG_CONVENTION CheckIDP();

/*
    Функция IsDebuggerPresent считывает поле "BeingDebugged" в PEB,
    функция CheckPebIDP считывает это поле напрямую из памяти
*/
BOOL DBG_CONVENTION CheckPebIDP();

/*
    Отлаживаемый процесс получает характеристику в виде специальных
    флагов в PEB->NtGlobalFlag - эти флаги необходимы для валидации кучи
    в случае её разрушения из-за, например, неправильных указателей, 
    переданных в delete. Отладчик должен уметь детектить такие ошибки,
    поэтому для кучи выставляются 3 флага валидации: FLG_HEAP_ENABLE_TAIL_CHECK,
    FLG_HEAP_ENABLE_FREE_CHECK и FLG_HEAP_VALIDATE_PARAMETERS. Если эти флаги есть - 
    процесс отлаживают.
*/
BOOL DBG_CONVENTION CheckNtGlobalFlag();

// Отцепляем текущий поток от отладчика: NtSetInformationThread(ThreadHideFromDebugger, ...)
VOID DBG_CONVENTION DetachFromDebugger(OPTIONAL HANDLE hThread = NULL);

/*
    Функцией NtQueryInformationProcess получаю сразу 3 отладочных характеристики из
    ядерной структуры EPROCESS: :
    наличие отладочного порта (через который отладчик и процесс обмениваются сообщениями),
    флага отладки и хэндла объекта отладчика:
*/
BOOL DBG_CONVENTION CheckDebugPortPresent();
BOOL DBG_CONVENTION CheckDebugFlagsPresent();
BOOL DBG_CONVENTION CheckDebugObjectPresent();

// Проверка на наличие ядерного отладчика (например, WinDBG + Kd через COM-порт на виртуалке или LiveKd):
// NtQuerySystemInformation(..., SystemKernelDebuggerInformation, ...)
BOOL DBG_CONVENTION CheckKernelDebuggerPresent();

/*
    Трюк основан на применении маски вывода отладочных сообщений.
    Если процесс отлаживается, функция NtSetDbgFilterState должна
    вернуть STATUS_SUCCESS (0x00000000).
    Статья: https://repo.palkeo.com/repositories/ivanlefou/todo/NtSetDebugFilterState.pdf
    НО! На Windows 10 она возвращает STATUS_SUCCESS даже когда отладчика нет.
    Поэтому очень НЕ рекомендуется использовать её в продакшне.
*/
BOOL DBG_CONVENTION CheckDbgFilterState(); // Поосторожнее с желаниями

// Смотрим, взведён ли флаг трассировки: EFLAGS -> [TrapFlag bit]:
BOOL DBG_CONVENTION CheckTrapFlag();

/*
    Следующий блок трюков основан на различном поведении инструкций
    и исключений при наличии отладчика и без него
*/

// Обработка исключений:

// Закрываем невалидный хэндл. С отладчиком будет вызвано исключение, без отладчика - не будет:
BOOL DBG_CONVENTION CheckNtClose();

// DbgBreakPoint из ntdll.dll - если есть отладчик, будет обработано как точка остановки,
// если отладчика нет - будет вызвано исключение, которое мы поймаем через __try..__except:
BOOL DBG_CONVENTION CheckDbgBreakPoint();

/*
    Генерим исключение через NtRaiseException:
    без отладчика попадём в __except:
*/
BOOL DBG_CONVENTION CheckNtRaiseException(); // Не использовать!

#ifdef _X86_

// Аналогично предыдущему пункту, только через непосредственный инлайн машинного кода 0xCC (точка остановки):
BOOL DBG_CONVENTION CheckInt3byCC();

/*
    Точка остановки - третье прерывание - может быть закодировано
    или через отдельную инструкцию (0xCC, мнемоники нет),
    или в явном виде через прерывание (0xCD 0x03 -> int 0x03),
    действует аналогично двум предыдущим пунктам, НО поведение
    обработчика прерывания в новых версиях Windows было изменено,
    и работать именно этот трюк не будет:
*/
BOOL DBG_CONVENTION CheckInt3byCD03(); // Не использовать!

/*
    Прерывание 0x2C - если отладчик есть, в EDX будет -1,
    без отладчика в EDX адрес следующей инструкции:
*/
BOOL DBG_CONVENTION CheckInt2C(); // Не использовать!

/*
    Источники:
    - https://forum.reverse4you.org/showthread.php?t=1329
    - http://resources.infosecinstitute.com/step-by-step-tutorial-on-reverse-engineering-malware-the-zeroaccessmaxsmiscer-crimeware-rootkit/
    Трюк с расщеплением байта: после прерывания 0x2D
    следующий байт будет пропущен, что вызовет исключение,
    которое без отладчика будет передано программе (__try..__except),
    а с отладчиком будет передану ему:
*/
BOOL DBG_CONVENTION CheckInt2D();

/*
    Точка остановки, аналог взведения TrapFlag в EFLAGS,
    включает пошаговое исполнение. Если отладчика нет - эксепшн,
    который мы ловим в __try..__except:
*/
BOOL DBG_CONVENTION CheckFrostPointF1(); // Не использовать!

/*
    Взводим флаг трассировки (бит TrapFlag в EFLAGS),
    без отладчика попадём в __except, с отладчиком
    исключения не будет:
*/
BOOL DBG_CONVENTION CheckTrapException(); // Не использовать!

#endif

// Импорты NativeAPI:

extern "C"
__declspec(dllimport)
NTSTATUS __stdcall 
NtSetInformationThread(
    HANDLE hThread, 
    THREAD_INFORMATION_CLASS ThreadInformationClass, 
    PVOID ThreadInformation, 
    ULONG ThreadInformationLength
);

extern "C"
__declspec(dllimport)
NTSTATUS __stdcall
NtSetDebugFilterState(
    ULONG ComponentId,
    ULONG Level,
    BOOLEAN State
);

extern "C"
__declspec(dllimport)
NTSTATUS __stdcall
DbgBreakPoint();


extern "C"
__declspec(dllimport)
NTSTATUS __stdcall
NtRaiseException(
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ThreadContext,
    BOOLEAN HandleException
);

// Определения энумов и андок-структур http://hex.pp.ua/nt/
namespace NTDEFINES {
    typedef enum _THREAD_INFORMATION_CLASS {
        ThreadBasicInformation,
        ThreadTimes,
        ThreadPriority,
        ThreadBasePriority,
        ThreadAffinityMask,
        ThreadImpersonationToken,
        ThreadDescriptorTableEntry,
        ThreadEnableAlignmentFaultFixup,
        ThreadEventPair,
        ThreadQuerySetWin32StartAddress,
        ThreadZeroTlsCell,
        ThreadPerformanceCount,
        ThreadAmILastThread,
        ThreadIdealProcessor,
        ThreadPriorityBoost,
        ThreadSetTlsArrayAddress,
        ThreadIsIoPending,
        ThreadHideFromDebugger
    } THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

    typedef enum _PROCESS_INFORMATION_CLASS {
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        ProcessDeviceMap,
        ProcessSessionInformation,
        ProcessForegroundInformation,
        ProcessWow64Information,
        ProcessImageFileName,
        ProcessLUIDDeviceMapsEnabled,
        ProcessBreakOnTermination,
        ProcessDebugObjectHandle,
        ProcessDebugFlags,
        ProcessHandleTracing,
        ProcessIoPriority,
        ProcessExecuteFlags,
        ProcessTlsInformation,
        ProcessCookie,
        ProcessImageInformation,
        ProcessCycleTime,
        ProcessPagePriority,
        ProcessInstrumentationCallback,
        ProcessThreadStackAllocation,
        ProcessWorkingSetWatchEx,
        ProcessImageFileNameWin32,
        ProcessImageFileMapping,
        ProcessAffinityUpdateMode,
        ProcessMemoryAllocationMode,
        ProcessGroupInformation,
        ProcessTokenVirtualizationEnabled,
        ProcessOwnerInformation,
        ProcessWindowInformation,
        ProcessHandleInformation,
        ProcessMitigationPolicy,
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount,
        ProcessRevokeFileHandles,
        ProcessWorkingSetControl,
        ProcessHandleTable,
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation,
        ProcessProtectionInformation,
        MaxProcessInfoClass
    } PROCESS_INFORMATION_CLASS, *PPROCESS_INFORMATION_CLASS;

    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemObsolete0,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation
    } SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
}

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

BOOL DBG_CONVENTION CheckRDP() {
    BOOL RemoteDebuggerPresent;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &RemoteDebuggerPresent);
    return RemoteDebuggerPresent;
}

BOOL DBG_CONVENTION CheckIDP() {
    return IsDebuggerPresent();
}

BOOL DBG_CONVENTION CheckPebIDP() {
    return GetPEB()->BeingDebugged;
}

BOOL DBG_CONVENTION CheckNtGlobalFlag() {
#define FLG_HEAP_ENABLE_TAIL_CHECK		(0x10)
#define FLG_HEAP_ENABLE_FREE_CHECK		(0x20)
#define FLG_HEAP_VALIDATE_PARAMETERS	(0x40)
#define DBG_SUMMARY_FLAG	(FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

#ifdef _AMD64_
#define NT_GLOBAL_FLAG_OFFSET 0x68
#else
#define NT_GLOBAL_FLAG_OFFSET 0xBC
#endif

    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)GetPEB() + NT_GLOBAL_FLAG_OFFSET);
    return (NtGlobalFlag & DBG_SUMMARY_FLAG) != 0;
}

VOID DBG_CONVENTION DetachFromDebugger(OPTIONAL HANDLE hThread) {
    NtSetInformationThread(hThread == NULL ? GetCurrentThread() : hThread, (THREAD_INFORMATION_CLASS)NTDEFINES::ThreadHideFromDebugger, NULL, 0);
}

BOOL DBG_CONVENTION CheckDebugPortPresent() {
    HANDLE DebugPort;
    NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)NTDEFINES::ProcessDebugPort, &DebugPort, sizeof(DebugPort), NULL);
    return DebugPort != NULL;
}

BOOL DBG_CONVENTION CheckDebugFlagsPresent() {
    BOOL NoDebugInherit = FALSE;
    NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)NTDEFINES::ProcessDebugFlags, &NoDebugInherit, sizeof(NoDebugInherit), NULL);
    return !NoDebugInherit;
}

BOOL DBG_CONVENTION CheckDebugObjectPresent() {
    HANDLE DebugObjectHandle;
    NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)NTDEFINES::ProcessDebugObjectHandle, &DebugObjectHandle, sizeof(DebugObjectHandle), NULL);
    return DebugObjectHandle != NULL;
}

BOOL DBG_CONVENTION CheckKernelDebuggerPresent() {
    // Проверяем взведённость системных флажков, отвечающих за наличие ядерного отладчика:
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemKernelDebuggerInfo;
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)NTDEFINES::SystemKernelDebuggerInformation, &SystemKernelDebuggerInfo, sizeof(SystemKernelDebuggerInfo), NULL);
    return SystemKernelDebuggerInfo.DebuggerEnabled && !SystemKernelDebuggerInfo.DebuggerNotPresent;
}

BOOL DBG_CONVENTION CheckDbgFilterState() {
    // Сбрасываем фильтрацию отладочных сообщений:
    return NtSetDebugFilterState(0, 0, TRUE) == ERROR_SUCCESS;
}

BOOL DBG_CONVENTION CheckNtClose() {
    __try {
        NtClose((HANDLE)0x1EE7C0DE); // Закрываем невалидный хэндл
        return FALSE; // Исключений не было, отладчика нет
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return TRUE; // Было сгенерено исключение, есть отладчик
    }
}

BOOL DBG_CONVENTION CheckDbgBreakPoint() {
    __try {
        DbgBreakPoint(); // Генерация брейкпоинта через NativeAPI
        return TRUE; // Брейкпоинт обработан, есть отладчик
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Брейкпоинт не обработан, отладчика нет
    }
}

BOOL DBG_CONVENTION CheckNtRaiseException() {
    __try {
        CONTEXT Context;
        RtlCaptureContext(&Context);

        EXCEPTION_RECORD ExceptionRecord;
        ExceptionRecord.ExceptionCode = EXCEPTION_INVALID_HANDLE;
        ExceptionRecord.ExceptionFlags = 0; // EXCEPTION_CONTINUABLE
        ExceptionRecord.ExceptionAddress = 0x00000000;
        ExceptionRecord.ExceptionRecord = &ExceptionRecord;
        ExceptionRecord.NumberParameters = 0;
        
        NtRaiseException(&ExceptionRecord, &Context, TRUE); // Поднимаем исключение
        return TRUE; // Обработано, есть отладчик
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Не обработано, отладчика нет
    }
}

#ifdef _X86_

BOOL DBG_CONVENTION CheckInt3byCC() {
    __try {
        __asm __emit 0xCC; // int 0x03 (0xCC)
        return TRUE; // Брейкпоинт обработан, есть отладчик
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Брейкпоинт не обработан, отладчика нет
    }
}

BOOL DBG_CONVENTION CheckInt3byCD03() {
    __try {
        __asm {
            nop
            __emit 0xCD // --+
            __emit 0x03 // --+--> int 03h (0xCD 0x03)
            nop
        }
        return TRUE; // Брейкпоинт обработан, есть отладчик
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Брейкпоинт не обработан, отладчика нет
    }
}

BOOL DBG_CONVENTION CheckInt2C() {
    __try {
        DWORD _EDX = 0;
        __asm {
            int 0x2C
            mov _EDX, edx
        }
        return _EDX == 0xFFFFFFFF; // Если есть отладчик, EDX равен -1
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOL DBG_CONVENTION CheckInt2D() {
    __try {
        __asm {
            int 0x2D // Пропуск байта
            nop
        }
        return TRUE; // Исключение обработано отладчиком
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Отладчика нет, исключение не обработано
    }
}

BOOL DBG_CONVENTION CheckFrostPointF1() {
    __try {
        __asm __emit 0xF1; // Машинный код точки заморозки (0xF1)
        return TRUE; // Обработано (Single-Step), есть отладчик
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Нет отладчика, исключение не обработано
    }
}

BOOL DBG_CONVENTION CheckTrapException() {
    __try {
        __asm {
            pushfd	// Кладём EFLAGS на стек
            or [esp], 0x100 // Взводим TrapFlag
            popfd	// Загружаем новый EFLAGS
            nop		// Здесь должен быть Single-Step
        }
        return TRUE; // Исключение обработано отладчиком, нас отлаживают
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE; // Исключение не обработано, отладчика нет
    }
}

BOOL DBG_CONVENTION CheckTrapFlag() {
    BOOL TrapFlag = FALSE;
    __asm {
        pushfd			// Кладём на стек регистр флагов
        pop eax			// Со стека в EAX
        and eax, 0x100	// Проверяем взведённость бита TrapFlag
        mov TrapFlag, eax 
    }
    return TrapFlag; // Если флаг не взведён - всё ок, нас не трассируют
}

#endif