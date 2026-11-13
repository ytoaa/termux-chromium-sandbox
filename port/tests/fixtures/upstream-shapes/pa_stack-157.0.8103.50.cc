// Upstream Chromium 157.0.8103.50 stack.cc (verbatim slice, lines 1-82 of
// base/allocator/partition_allocator/src/partition_alloc/stack/stack.cc).
// Round 33 fixture: GetStackTop() returns uintptr_t and the POSIX arm is an
// #elif (upstream refactor) — the R8 anchor must select the 157 variant.
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "partition_alloc/stack/stack.h"

#include <cstdint>
#include <limits>

#include "partition_alloc/build_config.h"
#include "partition_alloc/buildflags.h"
#include "partition_alloc/internal/partition_root_internal.h"
#include "partition_alloc/partition_alloc_base/compiler_specific.h"
#include "partition_alloc/partition_alloc_check.h"

#if PA_BUILDFLAG(IS_WIN)
#include <windows.h>
#else
#include <pthread.h>
#endif

#if PA_BUILDFLAG(PA_LIBC_GLIBC)
extern "C" void* __libc_stack_end;
#endif

namespace partition_alloc::internal {

#if PA_BUILDFLAG(IS_WIN)

uintptr_t GetStackTop() {
#if PA_BUILDFLAG(PA_ARCH_CPU_X86_64)
  return static_cast<uintptr_t>(
      reinterpret_cast<NT_TIB64*>(NtCurrentTeb())->StackBase);
#elif PA_BUILDFLAG(PA_ARCH_CPU_32_BITS)
  return reinterpret_cast<uintptr_t>(
      reinterpret_cast<NT_TIB*>(NtCurrentTeb())->StackBase);
#elif PA_BUILDFLAG(PA_ARCH_CPU_ARM64)
  // Windows 8 and later, see
  // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadstacklimits
  ULONG_PTR lowLimit, highLimit;
  ::GetCurrentThreadStackLimits(&lowLimit, &highLimit);
  return static_cast<uintptr_t>(highLimit);
#else
#error "Unsupported GetStackStart"
#endif
}

#elif PA_BUILDFLAG(IS_APPLE)

uintptr_t GetStackTop() {
  return reinterpret_cast<uintptr_t>(pthread_get_stackaddr_np(pthread_self()));
}

#elif PA_BUILDFLAG(IS_POSIX) || PA_BUILDFLAG(IS_FUCHSIA)

uintptr_t GetStackTop() {
  pthread_attr_t attr;
  int error = pthread_getattr_np(pthread_self(), &attr);
  if (!error) {
    void* base;
    size_t size;
    error = pthread_attr_getstack(&attr, &base, &size);
    PA_CHECK(!error);
    pthread_attr_destroy(&attr);
    return reinterpret_cast<uintptr_t>(base) + size;
  }

#if PA_BUILDFLAG(PA_LIBC_GLIBC)
  // pthread_getattr_np can fail for the main thread. In this case
  // just like NaCl we rely on the __libc_stack_end to give us
  // the start of the stack.
  // See https://code.google.com/p/nativeclient/issues/detail?id=3431.
  return reinterpret_cast<uintptr_t>(__libc_stack_end);
#else
  return 0;
#endif  // PA_BUILDFLAG(PA_LIBC_GLIBC)
}

#else  // PA_BUILDFLAG(IS_WIN)
#error "Unsupported GetStackTop"
#endif  // PA_BUILDFLAG(IS_WIN)

}  // namespace partition_alloc::internal
