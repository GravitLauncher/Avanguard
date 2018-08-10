#pragma once

#define DEBUG_OUTPUT

//#define SELF_REMAPPING /* Ремаппинг кодовой секции Avanguard.dll с RX-правами, experimental */

#define SKIP_VIRTUAL_INPUT /* Анти-кликеры и анти-макросы */

#define STRICT_DACLs        /* Урезать права, с которыми могут открыть наш процесс */
//#define MITIGATIONS       /* Сажает FPS с JIT'ом */
#define SKIP_APP_INIT_DLLS  /* Предотвращать инжект через AppInitDlls */
#define THREADS_FILTER      /* Предотвращать инжект через CreateRemoteThread */
#define MODULES_FILTER      /* Собирать информацию о загружаемых модулях */
#define APC_FILTER          /* Предотвращать инжект через APC */
#define MEMORY_FILTER       /* Собирать информацию о выделенной памяти */
#define STACKTRACE_CHECK    /* Если есть JIT, использовать ТОЛЬКО с MEMORY_FILTER */
#define TIMERED_CHECKINGS   /* Проверки по таймеру */

#define JAVA_BINDINGS   /* Поддержка привязки к Java через JNI */

#ifdef MODULES_FILTER
    // Предотвращать инжект через оконные хуки:
    #define WINDOWS_HOOKS_FILTER
#endif

#if defined MODULES_FILTER && defined MEMORY_FILTER
    // Отслеживать угон контекста:
    #define CONTEXT_FILTER
#endif

#ifdef TIMERED_CHECKINGS
    // Период проверки:
    #define TIMER_INTERVAL getTstTime()
	int getTstTime();
	void setTstTime(int);
    #ifdef MODULES_FILTER
        #define FIND_CHANGED_MODULES /* Искать модифицированные модули */
        #ifdef FIND_CHANGED_MODULES
            // Модули, в которых не допускается модификация:
            #define CRITICAL_MODULES { L"jvm.dll", L"java.dll" }
        #endif
    #endif

    #ifdef MEMORY_FILTER
        // Искать память, выделенную из чужих процессов:
        #define FIND_UNKNOWN_MEMORY
    #endif

    // Закрывать свои хэндлы в чужих процессах:
    //#define HANDLES_KEEPER
#endif