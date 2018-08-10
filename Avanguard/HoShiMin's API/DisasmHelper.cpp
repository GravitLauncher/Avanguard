#include "stdafx.h"

#define ZYDIS_STATIC_DEFINE
#include "..\\Zydis\\Zydis\\Zydis.h"

#include <string>

#include "DisasmHelper.h"

std::string disassemble(
    _OnDisassembleCallback callback,
    void* code,
    void* base_address,
    int instructions_count,
    CODE_ARCH arch
) {
    if (arch == arch_native) {
#ifdef _AMD64_
        arch = arch_x64;
#else if defined _X86_
        arch = arch_x86;
#endif
    }

    // Initialize decoder context:
    ZydisDecoder decoder;
    switch (arch) {
    case arch_x86:
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
        break;
    case arch_x64:
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
        break;
    default:
        return std::string("Invalid architecture type");
    }

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    std::string result;
    int instructions_counter = 0;

    uint64_t instructionPointer = (uint64_t)base_address;
    uint8_t* readPointer = (uint8_t*)code;
    size_t length = (size_t)instructions_count * 24;
    ZydisDecodedInstruction instruction;
    while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, readPointer, length, instructionPointer, &instruction))) {
        if (instructions_counter == instructions_count) break;

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer));

        char address[32];
        sprintf_s(address, "0x%016I64X\t", (uint64_t)instructionPointer);
        result += std::string(address) + buffer + std::string("\r\n");

        if (callback)
            if (!callback((void*)readPointer, (void*)instructionPointer, instruction.length, buffer)) break;

        readPointer += instruction.length;
        length -= instruction.length;
        instructionPointer += instruction.length;

        instructions_counter++;
    }

    return result;
}