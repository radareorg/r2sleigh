/* A qemu-user TCG plugin counting every guest instruction of one process (ROADMAP D343, x86-64):
 * each block adds its instruction count as it starts, and the total is written to `out=PATH` at
 * exit. Single-vCPU guests only: the inline add is not atomic. census.py `count` builds and runs it. */
#include <qemu-plugin.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t g_count;
static char g_out[4096];

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64, &g_count,
                                             qemu_plugin_tb_n_insns(tb));
}

static void at_exit(qemu_plugin_id_t id, void *unused)
{
    (void)id, (void)unused;
    FILE *out = fopen(g_out, "w");
    if (out) {
        fprintf(out, "%" PRIu64 "\n", g_count);
        fclose(out);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info;
    if (argc != 1 || strncmp(argv[0], "out=", 4) != 0 || strlen(argv[0] + 4) >= sizeof g_out)
        return -1;
    strcpy(g_out, argv[0] + 4);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
