#pragma once

#define ASMJIT_BUILD_STATIC
#define ASMJIT_BUILD_X86 

#define _SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "targetver.h"

#include <stdio.h>

#define NOMINMAX
#include "hModules.h"

#ifdef _DEBUG
#define XORSTR(Text) (Text)
#else
#include "xorstr\\xorstr.hpp"
#define XORSTR(Text) (xorstr(Text).crypt_get())
#endif