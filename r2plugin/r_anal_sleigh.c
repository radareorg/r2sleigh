/* radare2 - LGPL - Copyright 2025 - r2sleigh project */

#include <r_anal.h>
#include <r_core.h>
#include <r_lib.h>

/* FFI declarations for r2sleigh Rust library */
typedef struct R2ILContext R2ILContext;
typedef struct R2ILBlock R2ILBlock;

/* Context management */
extern R2ILContext *r2il_arch_init(const char *arch);
extern void r2il_free(R2ILContext *ctx);
extern int r2il_is_loaded(const R2ILContext *ctx);
extern const char *r2il_arch_name(const R2ILContext *ctx);
extern const char *r2il_error(const R2ILContext *ctx);

/* Lifting */
extern R2ILBlock *r2il_lift(R2ILContext *ctx, const unsigned char *bytes, size_t len, unsigned long long addr);
extern void r2il_block_free(R2ILBlock *block);

/* Block inspection */
extern size_t r2il_block_op_count(const R2ILBlock *block);
extern unsigned int r2il_block_size(const R2ILBlock *block);
extern unsigned long long r2il_block_addr(const R2ILBlock *block);
extern unsigned int r2il_block_type(const R2ILBlock *block);
extern unsigned long long r2il_block_jump(const R2ILBlock *block);
extern unsigned long long r2il_block_fail(const R2ILBlock *block);

/* ESIL/mnemonic */
extern char *r2il_block_to_esil(const R2ILContext *ctx, const R2ILBlock *block);
extern char *r2il_block_mnemonic(const R2ILContext *ctx, const unsigned char *bytes, size_t len, unsigned long long addr);
extern char *r2il_block_op_json(const R2ILBlock *block, size_t index);
extern void r2il_string_free(char *s);

/* Typed analysis */
extern char *r2il_block_regs_read(const R2ILContext *ctx, const R2ILBlock *block);
extern char *r2il_block_regs_write(const R2ILContext *ctx, const R2ILBlock *block);
extern char *r2il_block_mem_access(const R2ILContext *ctx, const R2ILBlock *block);
extern char *r2il_block_varnodes(const R2ILContext *ctx, const R2ILBlock *block);

/* SSA analysis */
extern char *r2il_block_to_ssa_json(const R2ILContext *ctx, const R2ILBlock *block);
extern char *r2il_block_defuse_json(const R2ILContext *ctx, const R2ILBlock *block);

/* Per-architecture context (lazy init) */
static R2ILContext *sleigh_ctx = NULL;
static char *sleigh_arch = NULL;

/* Minimum bytes to pass to libsla (it reads ahead for variable-length instructions) */
#define SLEIGH_MIN_BYTES 16

static R2ILContext *get_context(RAnal *anal) {
	const char *arch = anal->config->arch;
	int bits = anal->config->bits;

	/* Determine sleigh arch string */
	const char *sleigh_arch_str = NULL;
	if (!strcmp (arch, "x86")) {
		sleigh_arch_str = (bits == 64) ? "x86-64" : "x86";
	} else if (!strcmp (arch, "arm")) {
		sleigh_arch_str = "arm";
	} else {
		return NULL; /* unsupported arch */
	}

	/* Check if we need to reinitialize */
	if (sleigh_ctx && sleigh_arch && !strcmp (sleigh_arch, sleigh_arch_str)) {
		return sleigh_ctx;
	}

	/* Free old context */
	if (sleigh_ctx) {
		r2il_free (sleigh_ctx);
		sleigh_ctx = NULL;
	}
	free (sleigh_arch);
	sleigh_arch = NULL;

	/* Initialize new context */
	sleigh_ctx = r2il_arch_init (sleigh_arch_str);
	if (sleigh_ctx && r2il_is_loaded (sleigh_ctx)) {
		sleigh_arch = strdup (sleigh_arch_str);
		return sleigh_ctx;
	}

	if (sleigh_ctx) {
		const char *err = r2il_error (sleigh_ctx);
		if (err) {
			R_LOG_ERROR ("r2sleigh: %s", err);
		}
		r2il_free (sleigh_ctx);
		sleigh_ctx = NULL;
	}
	return NULL;
}

static int sleigh_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	R_RETURN_VAL_IF_FAIL (anal && op && data, -1);

	R2ILContext *ctx = get_context (anal);
	if (!ctx) {
		return -1;
	}

	/* Ensure we have enough bytes for libsla */
	ut8 buf[SLEIGH_MIN_BYTES];
	int use_len = len;
	const ut8 *use_data = data;

	if (len < SLEIGH_MIN_BYTES) {
		memset (buf, 0, sizeof (buf));
		memcpy (buf, data, len);
		use_data = buf;
		use_len = SLEIGH_MIN_BYTES;
	}

	/* Lift the instruction */
	R2ILBlock *block = r2il_lift (sleigh_ctx, use_data, use_len, addr);
	if (!block) {
		return -1;
	}

	/* Fill RAnalOp fields */
	op->addr = addr;
	op->size = r2il_block_size (block);
	op->type = r2il_block_type (block);

	ut64 jump_addr = r2il_block_jump (block);
	if (jump_addr != 0) {
		op->jump = jump_addr;
	}

	ut64 fail_addr = r2il_block_fail (block);
	if (fail_addr != 0) {
		op->fail = fail_addr;
	}

	/* Get mnemonic if requested */
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char *mnem = r2il_block_mnemonic (ctx, use_data, use_len, addr);
		if (mnem) {
			op->mnemonic = mnem; /* ownership transferred */
		}
	}

	/* Get ESIL if requested */
	if (mask & R_ARCH_OP_MASK_ESIL) {
		char *esil = r2il_block_to_esil (ctx, block);
		if (esil) {
			r_strbuf_set (&op->esil, esil);
			r2il_string_free (esil);
		}
	}

	r2il_block_free (block);
	return op->size;
}

static bool sleigh_init(RAnal *anal) {
	(void)anal; /* Lazy init - context created on first use */
	return true;
}

static bool sleigh_fini(RAnal *anal) {
	(void)anal;
	if (sleigh_ctx) {
		r2il_free (sleigh_ctx);
		sleigh_ctx = NULL;
	}
	free (sleigh_arch);
	sleigh_arch = NULL;
	return true;
}

static bool sleigh_cmd(RAnal *anal, const char *cmd) {
	if (!r_str_startswith (cmd, "sleigh")) {
		return false;
	}

	RCore *core = anal->coreb.core;
	RCons *cons = core ? core->cons : NULL;

	if (cmd[6] == '?') {
		if (cons) {
			r_cons_println (cons, "| a:sleigh        - Show r2sleigh status");
			r_cons_println (cons, "| a:sleigh.info   - Show current architecture info");
			r_cons_println (cons, "| a:sleigh.json   - Dump r2il ops as JSON for current instruction");
			r_cons_println (cons, "| a:sleigh.regs   - Show registers read/written by instruction");
			r_cons_println (cons, "| a:sleigh.mem    - Show memory accesses by instruction");
			r_cons_println (cons, "| a:sleigh.vars   - Show all varnodes used by instruction");
			r_cons_println (cons, "| a:sleigh.ssa    - Show SSA form of instruction");
			r_cons_println (cons, "| a:sleigh.defuse - Show def-use analysis of instruction");
		}
		return true;
	}

	if (!strcmp (cmd, "sleigh") || !strcmp (cmd, "sleigh.info")) {
		R2ILContext *ctx = get_context (anal);
		if (ctx) {
			const char *name = r2il_arch_name (ctx);
			if (cons) {
				r_cons_printf (cons, "r2sleigh: loaded architecture '%s'\n", name ? name : "unknown");
			}
		} else {
			if (cons) {
				r_cons_println (cons, "r2sleigh: no architecture loaded (unsupported or init failed)");
			}
		}
		return true;
	}

	if (!strcmp (cmd, "sleigh.json")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current seek */
		ut64 addr = core->addr;

		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return true;
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return true;
		}

		size_t count = r2il_block_op_count (block);
		if (cons) {
			r_cons_println (cons, "[");
		}
		size_t i;
		for (i = 0; i < count; i++) {
			char *json = r2il_block_op_json (block, i);
			if (json && cons) {
				r_cons_printf (cons, "  %s%s\n", json, (i + 1 < count) ? "," : "");
				r2il_string_free (json);
			}
		}
		if (cons) {
			r_cons_println (cons, "]");
		}

		r2il_block_free (block);
		return true;
	}

	if (!strcmp (cmd, "sleigh.regs")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return true;
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return true;
		}

		char *read_json = r2il_block_regs_read (ctx, block);
		char *write_json = r2il_block_regs_write (ctx, block);

		if (cons) {
			r_cons_printf (cons, "{\"read\":%s,\"write\":%s}\n",
				read_json ? read_json : "[]",
				write_json ? write_json : "[]");
		}

		r2il_string_free (read_json);
		r2il_string_free (write_json);
		r2il_block_free (block);
		return true;
	}

	if (!strcmp (cmd, "sleigh.mem")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return true;
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return true;
		}

		char *mem_json = r2il_block_mem_access (ctx, block);
		if (cons && mem_json) {
			r_cons_printf (cons, "%s\n", mem_json);
		}

		r2il_string_free (mem_json);
		r2il_block_free (block);
		return true;
	}

	if (!strcmp (cmd, "sleigh.vars")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return true;
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return true;
		}

		char *vars_json = r2il_block_varnodes (ctx, block);
		if (cons && vars_json) {
			r_cons_printf (cons, "%s\n", vars_json);
		}

		r2il_string_free (vars_json);
		r2il_block_free (block);
		return true;
	}

	if (!strcmp (cmd, "sleigh.ssa")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return true;
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return true;
		}

		char *ssa_json = r2il_block_to_ssa_json (ctx, block);
		if (cons && ssa_json) {
			r_cons_printf (cons, "%s\n", ssa_json);
		}

		r2il_string_free (ssa_json);
		r2il_block_free (block);
		return true;
	}

	if (!strcmp (cmd, "sleigh.defuse")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return true;
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return true;
		}

		char *defuse_json = r2il_block_defuse_json (ctx, block);
		if (cons && defuse_json) {
			r_cons_printf (cons, "%s\n", defuse_json);
		}

		r2il_string_free (defuse_json);
		r2il_block_free (block);
		return true;
	}

	R_LOG_ERROR ("Unknown subcommand. See 'a:sleigh?' for help");
	return true;
}

RAnalPlugin r_anal_plugin_sleigh = {
	.meta = {
		.name = "sleigh",
		.desc = "Sleigh-based analysis via r2sleigh (P-code to ESIL)",
		.license = "LGPL3",
		.author = "r2sleigh project",
	},
	.init = sleigh_init,
	.fini = sleigh_fini,
	.op = sleigh_op,
	.cmd = sleigh_cmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sleigh,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
