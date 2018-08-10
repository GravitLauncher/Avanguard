// [AsmJit]
// Complete x86/x64 JIT and Remote Assembler for C++.
//
// [License]
// ZLIB - See LICENSE.md file in the package.

// [Guard]
#ifndef _ASMJIT_CORE_SMALLSTRING_H
#define _ASMJIT_CORE_SMALLSTRING_H

// [Dependencies]
#include "../core/globals.h"
#include "../core/zone.h"

ASMJIT_BEGIN_NAMESPACE

//! \addtogroup asmjit_core_support
//! \{

// ============================================================================
// [asmjit::ZoneStringBase]
// ============================================================================

struct ZoneStringBase {
  inline void reset() noexcept {
    _dummy = nullptr;
    _external = nullptr;
  }

  Error setData(Zone* zone, uint32_t maxEmbeddedSize, const char* str, size_t size) noexcept {
    if (size == Globals::kNullTerminated)
      size = std::strlen(str);

    if (size <= maxEmbeddedSize) {
      std::memcpy(_embedded, str, size);
      _embedded[size] = '\0';
    }
    else {
      char* external = static_cast<char*>(zone->dup(str, size, true));
      if (ASMJIT_UNLIKELY(!external))
        return DebugUtils::errored(kErrorNoHeapMemory);
      _external = external;
    }

    _size = uint32_t(size);
    return kErrorOk;
  }

  // --------------------------------------------------------------------------
  // [Members]
  // --------------------------------------------------------------------------

  union {
    struct {
      uint32_t _size;
      char _embedded[sizeof(void*) * 2 - 4];
    };
    struct {
      void* _dummy;
      char* _external;
    };
  };
};

// ============================================================================
// [asmjit::ZoneString<N>]
// ============================================================================

//! Small string is a template that helps to create strings that can be either
//! statically allocated if they are small, or externally allocated in case
//! their size exceeds the limit. The `N` represents the size of the whole
//! `ZoneString` structure, based on that size the maximum size of the internal
//! buffer is determined.
template<size_t N>
class ZoneString {
public:
  static constexpr uint32_t kWholeSize =
    (N > sizeof(ZoneStringBase)) ? uint32_t(N) : uint32_t(sizeof(ZoneStringBase));
  static constexpr uint32_t kMaxEmbeddedSize = kWholeSize - 5;

  // --------------------------------------------------------------------------
  // [Construction / Destruction]
  // --------------------------------------------------------------------------

  inline ZoneString() noexcept { reset(); }
  inline void reset() noexcept { _base.reset(); }

  // --------------------------------------------------------------------------
  // [Accessors]
  // --------------------------------------------------------------------------

  inline const char* data() const noexcept { return _base._size <= kMaxEmbeddedSize ? _base._embedded : _base._external; }
  inline bool empty() const noexcept { return _base._size == 0; }
  inline uint32_t size() const noexcept { return _base._size; }

  inline bool isEmbedded() const noexcept { return _base._size <= kMaxEmbeddedSize; }

  inline Error setData(Zone* zone, const char* data, size_t size) noexcept {
    return _base.setData(zone, kMaxEmbeddedSize, data, size);
  }

  // --------------------------------------------------------------------------
  // [Members]
  // --------------------------------------------------------------------------

  union {
    ZoneStringBase _base;
    char _wholeData[kWholeSize];
  };
};

//! \}

ASMJIT_END_NAMESPACE

// [Guard]
#endif // _ASMJIT_CORE_SMALLSTRING_H
