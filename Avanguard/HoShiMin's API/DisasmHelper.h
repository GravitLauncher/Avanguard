#pragma once

#include <functional>

typedef enum _CODE_ARCH {
    arch_x86,
    arch_x64,
    arch_native
} CODE_ARCH, *PCODE_ARCH;

typedef std::function<bool(
    void* Code,
    void* BaseAddress,
    unsigned int InstructionLength,
    char* Disassembly
)> _OnDisassembleCallback;

std::string disassemble(
    _OnDisassembleCallback callback,
    void* code,
    void* base_address,
    int instructions_count,
    CODE_ARCH arch = arch_native
);