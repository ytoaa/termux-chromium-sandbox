/* Termux Chromium seccomp-only port: bionic pthread_getattr_np shield.
 *
 * WHY: bionic implements pthread_getattr_np() for the MAIN thread by reading
 * /proc/self/maps, and LOG(FATAL)s (-> abort()) when that read fails. Chromium
 * installs its seccomp-bpf policy on the main thread of every sandboxed child,
 * and that policy denies openat() - so ANY main-thread pthread_getattr_np()
 * call after "Activated seccomp-bpf sandbox for process type: renderer" kills
 * the process. Upstream only guards the callers it knows about, and only under
 * BUILDFLAG(IS_ANDROID) / __GLIBC__, neither of which matches a Termux build
 * (os=linux on bionic). The in-tree rules R7/R8 cover base::debug::GetStackEnd
 * and partition_alloc's stack top; this shim covers every remaining caller
 * (crash handlers, unwinders, future upstream code) by serving a snapshot.
 *
 * HOW: capture the main thread's pthread_attr_t during library load, i.e.
 * before any sandbox exists, and hand that snapshot to every main-thread
 * caller afterwards. Non-main threads fall through to the real function
 * (bionic serves those from pthread state, no /proc involved).
 *
 * SAFETY: the main thread's stack bounds never change for the life of the
 * process, so the snapshot is exact, not an approximation. If the snapshot
 * could not be taken we fall through and behave exactly like stock bionic.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>

static int (*g_real_gnp)(pthread_t, pthread_attr_t *);
static pthread_attr_t g_main_attr;
static int g_main_ok;

__attribute__((constructor)) static void termux_gnp_init(void) {
  g_real_gnp = (int (*)(pthread_t, pthread_attr_t *))
      dlsym(RTLD_NEXT, "pthread_getattr_np");
  g_main_ok = (g_real_gnp != 0) && (g_real_gnp(pthread_self(), &g_main_attr) == 0);
}

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr) {
  if (g_real_gnp == 0) {
    g_real_gnp = (int (*)(pthread_t, pthread_attr_t *))
        dlsym(RTLD_NEXT, "pthread_getattr_np");
  }
  /* Fork-safe main-thread test (Round 32): the constructor ran in the loading
   * process, and sandboxed children are forked from it -- never exec'd -- so
   * they inherit both this library and a byte-copy of the main stack mapping
   * at the same addresses. pthread_equal(thread, g_main_thread) is FALSE in
   * every forked child (the inherited tid belongs to the parent), which
   * silently disabled this shield in renderers; gettid()==getpid() identifies
   * the child's own main thread and the inherited snapshot bounds stay exact. */
  if (g_main_ok && attr != 0 && gettid() == getpid() &&
      pthread_equal(thread, pthread_self())) {
    *attr = g_main_attr;
    return 0;
  }
  return g_real_gnp != 0 ? g_real_gnp(thread, attr) : -1;
}
