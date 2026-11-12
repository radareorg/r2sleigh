/* A qemu-user TCG plugin counting the guest instructions of one call (ADR D343).
 * equiv_rt.c asks through a syscall no kernel defines: ARM zeroes the count and sets the
 * allowance, SETTLE stops it and writes it to the fd named (a guest fd is the host's under
 * qemu-user), HELLO writes a greeting there. Past the allowance it sends SIGPWR, as perf does. */
#include <qemu-plugin.h>

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* rt/equiv_rt.c's COUNTER_SYSCALL and COUNTER_* operations. */
#define COUNTER_SYSCALL 0x4551
enum { COUNTER_HELLO = 1, COUNTER_ARM = 2, COUNTER_SETTLE = 3 };
static const char COUNTER_HELLO_BYTES[8] = "EQCOUNT1";

static uint64_t g_count;    /* every vCPU's blocks add to it inline, armed or not */
static uint64_t g_allowance;
static int g_armed;
static pid_t g_caller;      /* the thread that armed: the one the budget signal stops */
static pid_t g_watching;    /* the process whose watcher runs; a forked child starts its own */

/* A block's instructions count as it starts (an inline add, no call): deterministic for one
 * qemu build. qemu 8.2 has no conditional callback, so a thread checks the allowance. */
static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64, &g_count,
                                             qemu_plugin_tb_n_insns(tb));
}

/* Every millisecond; the verdict is the count the runtime reads, never this latency. */
static void *watch(void *unused)
{
    (void)unused;
    const struct timespec tick = { 0, 1000000 };
    for (;;) {
        if (__atomic_load_n(&g_armed, __ATOMIC_ACQUIRE)
            && __atomic_load_n(&g_count, __ATOMIC_RELAXED) > g_allowance) {
            __atomic_store_n(&g_armed, 0, __ATOMIC_RELEASE);
            syscall(SYS_tgkill, getpid(), g_caller, SIGPWR);
        }
        nanosleep(&tick, NULL);
    }
    return NULL;
}

/* Started blocking every signal, so a process-directed one reaches qemu's vCPU thread. */
static void watch_start(void)
{
    sigset_t all, old;
    pthread_t thread;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &old);
    if (pthread_create(&thread, NULL, watch, NULL) == 0) {
        pthread_detach(thread);
        g_watching = getpid();
    }
    pthread_sigmask(SIG_SETMASK, &old, NULL);
}

static void on_syscall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t op,
                       uint64_t arg, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                       uint64_t a7, uint64_t a8)
{
    (void)id, (void)vcpu_index, (void)a3, (void)a4, (void)a5, (void)a6, (void)a7, (void)a8;
    if (num != COUNTER_SYSCALL)
        return;
    if (op == COUNTER_ARM) {
        if (g_watching != getpid())
            watch_start();
        g_caller = (pid_t)syscall(SYS_gettid);
        g_allowance = arg;
        __atomic_store_n(&g_count, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&g_armed, 1, __ATOMIC_RELEASE);
    } else if (op == COUNTER_SETTLE) {
        __atomic_store_n(&g_armed, 0, __ATOMIC_RELEASE);
        uint64_t count = __atomic_load_n(&g_count, __ATOMIC_RELAXED);
        (void)!pwrite((int)arg, &count, sizeof count, 0);
    } else if (op == COUNTER_HELLO) {
        (void)!pwrite((int)arg, COUNTER_HELLO_BYTES, sizeof COUNTER_HELLO_BYTES, 0);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info, (void)argc, (void)argv;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, on_syscall);
    return 0;
}
