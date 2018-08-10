#pragma once

#include <Windows.h>

// Работает, начиная с Vista SP1.
// На версиях ниже вызов всегда вернёт FALSE.

typedef BOOLEAN (CALLBACK *_KeSecuredMemoryCallback) (
    PVOID Address, SIZE_T Range
);

/*
    Устанавливает и удаляет каллбэки на изменение
    атрибутов доступа или освобождение защищённой памяти.
    Чтобы защитить память, необходимо в ядре вызвать
    функцию MmSecureVirtualMemory (необходим драйвер).

    Если указанная в параметрах каллбэка память была защищена,
    каллбэк обязан закрыть все отображения и вернуть TRUE.
    Если указанная в параметрах каллбэка память не попадает
    в защищённый диапазон, каллбэк должен вернуть FALSE.
*/
BOOL SetupSecuredMemoryCallback(_KeSecuredMemoryCallback Callback);
BOOL RemoveSecuredMemoryCallback();

