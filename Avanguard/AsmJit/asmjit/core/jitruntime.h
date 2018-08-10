// [AsmJit]
// Complete x86/x64 JIT and Remote Assembler for C++.
//
// [License]
// ZLIB - See LICENSE.md file in the package.

// [Guard]
#ifndef _ASMJIT_CORE_JITRUNTIME_H
#define _ASMJIT_CORE_JITRUNTIME_H

#include "../core/build.h"
#ifndef ASMJIT_DISABLE_JIT

#include "../core/codeholder.h"
#include "../core/jitallocator.h"
#include "../core/target.h"

ASMJIT_BEGIN_NAMESPACE

class CodeHolder;

//! \addtogroup asmjit_core_jit
//! \{

// ============================================================================
// [asmjit::JitRuntime]
// ============================================================================

//! JIT execution runtime is a special `Target` that is designed to store and
//! execute the generated code.
class ASMJIT_VIRTAPI JitRuntime : public Target {
public:
  ASMJIT_NONCOPYABLE(JitRuntime)

  // --------------------------------------------------------------------------
  // [Construction / Destruction]
  // --------------------------------------------------------------------------

  //! Create a `JitRuntime` instance.
  ASMJIT_API JitRuntime() noexcept;
  //! Destroy the `JitRuntime` instance.
  ASMJIT_API virtual ~JitRuntime() noexcept;

  // --------------------------------------------------------------------------
  // [Accessors]
  // --------------------------------------------------------------------------

  //! Get `JitAllocator` of the runtime.
  inline JitAllocator* allocator() const noexcept { return const_cast<JitAllocator*>(&_allocator); }

  // --------------------------------------------------------------------------
  // [Add / Release]
  // --------------------------------------------------------------------------

  // NOTE: To allow passing function pointers to `add()` and `release()` the
  // virtual methods are prefixed with `_` and called from templates instead.

  //! Allocate a memory needed for a code stored in the `CodeHolder` and
  //! relocate it to the target location.
  //!
  //! The beginning of the memory allocated for the function is returned in
  //! `dst`. If failed the `Error` code is returned and `dst` is set to null
  //! (this means that you don't have to set it to null before calling `add()`).
  template<typename Func>
  inline Error add(Func* dst, CodeHolder* code) noexcept {
    return _add(AsmJitInternal::ptr_cast<void**, Func*>(dst), code);
  }

  //! Release `p` which was obtained by calling `add()`.
  template<typename Func>
  inline Error release(Func p) noexcept {
    return _release(AsmJitInternal::ptr_cast<void*, Func>(p));
  }

  //! Type-unsafe version of `add()`.
  ASMJIT_API virtual Error _add(void** dst, CodeHolder* code) noexcept;

  //! Type-unsafe version of `release()`.
  ASMJIT_API virtual Error _release(void* p) noexcept;

  //! Flush an instruction cache.
  //!
  //! This member function is called after the code has been copied to the
  //! destination buffer. It is only useful for JIT code generation as it
  //! causes a flush of the processor's cache.
  //!
  //! Flushing is basically a NOP under X86, but is needed by architectures
  //! that do not have a transparent instruction cache like ARM.
  //!
  //! This function can also be overridden to improve compatibility with tools
  //! such as Valgrind, however, it's not an official part of AsmJit.
  ASMJIT_API virtual void flush(const void* p, size_t size) noexcept;

  // --------------------------------------------------------------------------
  // [Members]
  // --------------------------------------------------------------------------

  //! Virtual memory allocator.
  JitAllocator _allocator;
};

//! \}

ASMJIT_END_NAMESPACE

#endif
#endif
