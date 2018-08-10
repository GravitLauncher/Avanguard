#include "stdafx.h"

#include "JitHelper.h"

AsmJIT::AsmJIT(uint32_t ArchId, uint32_t ArchMode, uint64_t BaseAddress) 
: CodeInfo(ArchId, ArchMode, BaseAddress), CodeBuffer(NULL), CodeSize(0)
{
    CodeHolder.init(CodeInfo);
}

AsmJIT::~AsmJIT() {
    FreeCallable();
}

void AsmJIT::Add(const char* Instruction) {
    (CodeListing.append(Instruction)).append("\n");
}

void AsmJIT::Add(const std::string& Instruction) {
    Add(Instruction.c_str());
}

asmjit::Error AsmJIT::Build() {
    FreeCallable();
    asmjit::x86::Assembler Assembler(&CodeHolder);
    asmtk::AsmParser Parser(&Assembler);
    asmjit::Error Error = Parser.parse(CodeListing.c_str());
    asmjit::CodeBuffer& Buffer = CodeHolder.sectionEntry(0)->buffer();
    CodeBuffer = Buffer.data();
    CodeSize = Buffer.size();
    return Error;
}