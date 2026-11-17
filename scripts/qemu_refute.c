/* A qemu-user TCG plugin logging the loads and stores of the first 3 activations of each target
 * leaf (ROADMAP D467, x86-64): `entry=E_ENTRY,out=PATH,fn=START:END,...` in file addresses, each
 * `enter` by its file address, accesses by the machine's. Single vCPU; run_refuter.py builds it. */
#include <qemu-plugin.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_FUNCTIONS 64
#define ACTIVATIONS 3

static uint64_t g_start[MAX_FUNCTIONS], g_end[MAX_FUNCTIONS];
static unsigned g_entered[MAX_FUNCTIONS];
static int g_count;
static int g_active = -1;
static uint64_t g_file_entry;
static uint64_t g_bias;
static int g_biased;
static FILE *g_out;

/* Every instruction: entering a target starts an activation, any other address outside the
 * active target's extent ends it. */
static void insn_exec(unsigned int vcpu, void *data)
{
    uint64_t pc = (uint64_t)(uintptr_t)data;
    (void)vcpu;
    if (g_active >= 0 && (pc < g_start[g_active] || pc >= g_end[g_active])) {
        g_active = -1;
        fputs("leave\n", g_out);
    }
    for (int i = 0; i < g_count; i++) {
        if (pc == g_start[i] && g_entered[i] < ACTIVATIONS) {
            g_entered[i]++;
            g_active = i;
            fprintf(g_out, "enter %" PRIx64 " %u\n", pc - g_bias, g_entered[i]);
        }
    }
}

static void mem_access(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void *data)
{
    (void)vcpu, (void)data;
    if (g_active < 0)
        return;
    fprintf(g_out, "%s %" PRIx64 " %u\n", qemu_plugin_mem_is_store(info) ? "store" : "load", vaddr,
            1u << qemu_plugin_mem_size_shift(info));
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    /* The guest is loaded by its first translation: its targets move by the load bias once. */
    if (!g_biased) {
        g_bias = qemu_plugin_entry_code() - g_file_entry;
        for (int i = 0; i < g_count; i++)
            g_start[i] += g_bias, g_end[i] += g_bias;
        g_biased = 1;
    }
    for (size_t n = 0; n < qemu_plugin_tb_n_insns(tb); n++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, n);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec, QEMU_PLUGIN_CB_NO_REGS,
                                               (void *)(uintptr_t)pc);
        for (int i = 0; i < g_count; i++) {
            if (pc >= g_start[i] && pc < g_end[i]) {
                qemu_plugin_register_vcpu_mem_cb(insn, mem_access, QEMU_PLUGIN_CB_NO_REGS,
                                                 QEMU_PLUGIN_MEM_RW, NULL);
                break;
            }
        }
    }
}

static void at_exit(qemu_plugin_id_t id, void *unused)
{
    (void)id, (void)unused;
    fclose(g_out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info;
    const char *out = NULL;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "out=", 4) == 0)
            out = argv[i] + 4;
        else if (strncmp(argv[i], "entry=", 6) == 0)
            g_file_entry = strtoull(argv[i] + 6, NULL, 16);
        else if (strncmp(argv[i], "fn=", 3) == 0 && g_count < MAX_FUNCTIONS) {
            char *end;
            g_start[g_count] = strtoull(argv[i] + 3, &end, 16);
            if (*end != ':')
                return -1;
            g_end[g_count] = strtoull(end + 1, NULL, 16);
            g_count++;
        } else
            return -1;
    }
    if (out == NULL || g_file_entry == 0 || (g_out = fopen(out, "w")) == NULL)
        return -1;
    /* A recorder kills the guest at its last stop: each line is out before then. */
    setvbuf(g_out, NULL, _IOLBF, 0);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
