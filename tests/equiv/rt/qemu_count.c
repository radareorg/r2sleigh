/* A qemu-user TCG plugin counting the guest instructions of one call (ADR D343).
 * equiv_rt.c asks through a syscall no kernel defines: ARM zeroes the count and sets the
 * allowance, SETTLE stops it and writes it to the fd named (a guest fd is the host's under
 * qemu-user), HELLO writes a greeting there. Past the allowance it sends SIGPWR, as perf does. */
#include <qemu-plugin.h>

#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* rt/equiv_rt.c's COUNTER_SYSCALL and COUNTER_* operations. */
#define COUNTER_SYSCALL 0x4551
enum { COUNTER_HELLO = 1, COUNTER_ARM = 2, COUNTER_SETTLE = 3 };
static const char COUNTER_HELLO_BYTES[8] = "EQCOUNT1";

static uint64_t g_count;
static uint64_t g_allowance;
static int g_armed;
static unsigned int g_vcpu;

/* A block's instructions count as it starts: deterministic for one qemu build. */
static void tb_exec(unsigned int vcpu_index, void *n_insns)
{
    if (!g_armed || vcpu_index != g_vcpu)
        return;
    g_count += (uintptr_t)n_insns;
    if (g_count > g_allowance) {
        g_armed = 0;
        syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid), SIGPWR);
    }
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)qemu_plugin_tb_n_insns(tb));
}

static void on_syscall(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num, uint64_t op,
                       uint64_t arg, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                       uint64_t a7, uint64_t a8)
{
    (void)id, (void)a3, (void)a4, (void)a5, (void)a6, (void)a7, (void)a8;
    if (num != COUNTER_SYSCALL)
        return;
    if (op == COUNTER_ARM) {
        g_count = 0;
        g_allowance = arg;
        g_vcpu = vcpu_index;
        g_armed = 1;
    } else if (op == COUNTER_SETTLE) {
        g_armed = 0;
        (void)!pwrite((int)arg, &g_count, sizeof g_count, 0);
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
