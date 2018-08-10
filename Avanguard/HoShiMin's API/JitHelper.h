#pragma once

#include <string>
#include <asmtk.h>

#include <Windows.h>

class AsmJIT final {
private:
    asmjit::CodeInfo CodeInfo;
    asmjit::CodeHolder CodeHolder;
    std::string CodeListing;
    void* CodeBuffer;
    void* CallableBuffer;
    size_t CodeSize;
public:
    void* MakeCallable() {
        if (CallableBuffer) return CallableBuffer;
        void* CallableBuffer = VirtualAlloc(NULL, CodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        MoveMemory(CallableBuffer, CodeBuffer, CodeSize);
        return CallableBuffer;
    }

    void FreeCallable() {
        if (!CallableBuffer) return;
        VirtualFree(CallableBuffer, 0, MEM_RELEASE);
        CallableBuffer = NULL;
    }

    AsmJIT(uint32_t archId, uint32_t archMode = 0, uint64_t baseAddress = asmjit::Globals::kNoBaseAddress);
    ~AsmJIT();
    void Add(const char* Instruction);
    void Add(const std::string& Instruction);
    asmjit::Error Build();

    void* GetPtr() { return CodeBuffer; };
    size_t GetSize() { return CodeSize; };
};