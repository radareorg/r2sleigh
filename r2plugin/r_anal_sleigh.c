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
extern R2ILBlock *r2il_lift_block(R2ILContext *ctx, const unsigned char *bytes, size_t len, unsigned long long addr, unsigned int block_size);
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

/* SSA analysis (instruction-level) */
extern char *r2il_block_to_ssa_json(const R2ILContext *ctx, const R2ILBlock *block);
extern char *r2il_block_defuse_json(const R2ILContext *ctx, const R2ILBlock *block);

/* SSA analysis (function-level) */
extern char *r2ssa_function_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2ssa_function_opt_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2ssa_defuse_function_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2ssa_domtree_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2ssa_backward_slice_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, const char *var_name);
extern char *r2taint_function_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2taint_sources_sinks_json(const char *json);

/* Symbolic execution */
extern char *r2sym_function(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long entry_addr);
extern char *r2sym_paths(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long entry_addr);
extern int r2sym_merge_is_enabled(void);
extern void r2sym_merge_set_enabled(int enabled);

/* Decompiler */
extern char *r2dec_function(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, const char *func_name);

/* CFG */
extern char *r2cfg_function_ascii(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2cfg_function_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2il_get_reg_profile(const R2ILContext *ctx);
/* Per-architecture context (lazy init) */
static R2ILContext *sleigh_ctx = NULL;
static char *sleigh_arch = NULL;
static char *sleigh_arch_override = NULL;

/* Minimum bytes to pass to libsla (it reads ahead for variable-length instructions) */
#define SLEIGH_MIN_BYTES 16
#define SLEIGH_BLOCK_MAX_BYTES 256

/* Helper to lift all basic blocks of a function */
typedef struct {
	R2ILBlock **blocks;
	size_t count;
	size_t capacity;
} BlockArray;

static void block_array_init(BlockArray *arr) {
	arr->blocks = NULL;
	arr->count = 0;
	arr->capacity = 0;
}

static void block_array_push(BlockArray *arr, R2ILBlock *block) {
	if (arr->count >= arr->capacity) {
		arr->capacity = arr->capacity ? arr->capacity * 2 : 8;
		arr->blocks = realloc (arr->blocks, arr->capacity * sizeof (R2ILBlock *));
	}
	arr->blocks[arr->count++] = block;
}

static void block_array_free(BlockArray *arr) {
	size_t i;
	for (i = 0; i < arr->count; i++) {
		r2il_block_free (arr->blocks[i]);
	}
	free (arr->blocks);
	arr->blocks = NULL;
	arr->count = 0;
	arr->capacity = 0;
}

/* Lift all basic blocks of a function */
static bool lift_function_blocks(RAnal *anal, RAnalFunction *fcn, R2ILContext *ctx, BlockArray *out) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && ctx && out, false);

	RListIter *iter;
	RAnalBlock *bb;

	block_array_init (out);

	r_list_foreach (fcn->bbs, iter, bb) {
		ut8 buf[SLEIGH_BLOCK_MAX_BYTES];
		size_t bb_size = R_MIN (bb->size, sizeof (buf));
		size_t to_read = bb_size;

		if (!anal->iob.read_at (anal->iob.io, bb->addr, buf, to_read)) {
			R_LOG_ERROR ("r2sleigh: failed to read block at 0x%"PFMT64x, bb->addr);
			continue;
		}

		/* Ensure minimum bytes for libsla (it reads ahead for variable-length instructions) */
		if (to_read < SLEIGH_MIN_BYTES) {
			memset (buf + to_read, 0, SLEIGH_MIN_BYTES - to_read);
			to_read = SLEIGH_MIN_BYTES;
		}

		/* Lift entire basic block (multiple instructions) */
		R2ILBlock *block = r2il_lift_block (ctx, buf, to_read, bb->addr, (unsigned int)bb_size);
		if (block) {
			block_array_push (out, block);
		}
	}

	return out->count > 0;
}

static R2ILContext *get_context(RAnal *anal) {
	const char *arch = anal->config->arch;
	int bits = anal->config->bits;

	/* Determine sleigh arch string */
	const char *sleigh_arch_str;
	if (sleigh_arch_override) {
		sleigh_arch_str = sleigh_arch_override;
	} else if (!strcmp (arch, "x86")) {
		sleigh_arch_str = (bits == 64) ? "x86-64" : "x86";
	} else if (!strcmp (arch, "arm")) {
		sleigh_arch_str = "arm";
	} else if (!strcmp (arch, "mips")) {
        /* Simple heuristic for MIPS (assuming default is 32be/le) */
        /* Note: This is partial, better use manual override for complex variants */
		sleigh_arch_str = "mips"; /* Placeholder - mapped often to general mips */
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
	/* Initialize new context */
	sleigh_ctx = r2il_arch_init (sleigh_arch_str);
	if (sleigh_ctx && r2il_is_loaded (sleigh_ctx)) {
		sleigh_arch = strdup (sleigh_arch_str);

		/* Set register profile from Sleigh definitions */
		char *profile = r2il_get_reg_profile (sleigh_ctx);
		if (profile) {
			r_anal_set_reg_profile (anal, profile);
			r2il_string_free (profile);
		}

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
	if (!r_str_startswith (cmd, "sla")) {
		return false;
	}

	RCore *core = anal->coreb.core;
	RCons *cons = core ? core->cons : NULL;

	if (cmd[3] == '?') {
		if (cons) {
			r_cons_println (cons, "| a:sla        - Show r2sleigh status");
			r_cons_println (cons, "| a:sla.info   - Show current architecture info");
			r_cons_println (cons, "| a:sla.arch [name] - Get/Set Sleigh architecture manually");
			r_cons_println (cons, "| a:sla.json   - Dump r2il ops as JSON for current instruction");
			r_cons_println (cons, "| a:sla.regs   - Show registers read/written by instruction");
			r_cons_println (cons, "| a:sla.mem    - Show memory accesses by instruction");
			r_cons_println (cons, "| a:sla.vars   - Show all varnodes used by instruction");
			r_cons_println (cons, "| a:sla.ssa    - Show SSA form of instruction");
			r_cons_println (cons, "| a:sla.defuse - Show def-use analysis of instruction");
			r_cons_println (cons, "| a:sla.ssa.func - Show function SSA with phi nodes");
			r_cons_println (cons, "| a:sla.ssa.func.opt - Show optimized function SSA");
			r_cons_println (cons, "| a:sla.defuse.func - Show function-wide def-use analysis");
			r_cons_println (cons, "| a:sla.dom    - Show dominator tree for current function");
			r_cons_println (cons, "| a:sla.slice <var> - Backward slice from variable (e.g. rax_3)");
			r_cons_println (cons, "| a:sla.sym    - Symbolic execution summary for current function");
			r_cons_println (cons, "| a:sla.sym.paths - Explore paths in current function");
			r_cons_println (cons, "| a:sla.sym.merge [on|off] - Toggle symbolic state merging");
			r_cons_println (cons, "| a:sla.taint  - Taint analysis for current function");
			r_cons_println (cons, "| a:sla.dec    - Decompile current function to C");
			r_cons_println (cons, "| a:sla.cfg    - Show ASCII CFG for current function");
			r_cons_println (cons, "| a:sla.cfg.json - Show CFG as JSON for current function");
		}
		return true;
	}

	if (!strncmp (cmd, "sla.arch", 8)) {
		const char *arg = cmd + 8;
		if (*arg == ' ') {
			arg++; // skip space
			while (*arg == ' ') arg++;
			if (*arg) {
				/* Set override */
				free (sleigh_arch_override);
				sleigh_arch_override = strdup (arg);
				/* Force context reload on next use */
				if (sleigh_ctx) {
					r2il_free (sleigh_ctx);
					sleigh_ctx = NULL;
				}
				free (sleigh_arch);
				sleigh_arch = NULL;
				if (cons) {
					r_cons_printf (cons, "r2sleigh: architecture set to '%s' (reload deferred)\n", sleigh_arch_override);
				}
			}
		} else {
			/* Get current */
			R2ILContext *ctx = get_context (anal);
			const char *name = ctx ? r2il_arch_name (ctx) : NULL;
			if (cons) {
				if (name) {
					r_cons_printf (cons, "%s\n", name);
				} else {
					r_cons_println (cons, "none");
				}
			}
		}
		return true;
	}

	if (!strcmp (cmd, "sla") || !strcmp (cmd, "sla.info")) {
		R2ILContext *ctx = get_context (anal);
		if (ctx) {
			const char *name = r2il_arch_name (ctx);
			if (cons) {
				r_cons_printf (cons, "sla: loaded architecture '%s'\n", name ? name : "unknown");
			}
		} else {
			if (cons) {
				r_cons_println (cons, "sla: no architecture loaded (unsupported or init failed)");
			}
		}
		return true;
	}

	if (!strcmp (cmd, "sla.json")) {
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

	if (!strcmp (cmd, "sla.regs")) {
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

	if (!strcmp (cmd, "sla.mem")) {
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

	if (!strcmp (cmd, "sla.vars")) {
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

	if (!strcmp (cmd, "sla.ssa")) {
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

	if (!strcmp (cmd, "sla.defuse")) {
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

	/* ========== Function-level SSA commands ========== */

	if (!strcmp (cmd, "sla.ssa.func")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Get function SSA */
		char *result = r2ssa_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strcmp (cmd, "sla.ssa.func.opt")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		char *result = r2ssa_function_opt_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strcmp (cmd, "sla.defuse.func")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Get function def-use analysis */
		char *result = r2ssa_defuse_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strcmp (cmd, "sla.dom")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Get dominator tree */
		char *result = r2ssa_domtree_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strncmp (cmd, "sla.slice", 9)) {
		const char *arg = cmd + 9;
		if (*arg == ' ') {
			arg++;
			while (*arg == ' ') {
				arg++;
			}
		}

		if (!*arg) {
			if (cons) {
				r_cons_println (cons, "Usage: a:sla.slice <var_name>");
				r_cons_println (cons, "Example: a:sla.slice rax_3");
				r_cons_println (cons, "         a:sla.slice zf_1");
			}
			return true;
		}

		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Get backward slice */
		char *result = r2ssa_backward_slice_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, arg);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	/* ========== Function-level commands ========== */

	if (!strncmp (cmd, "sla.sym.merge", 13)) {
		const char *arg = cmd + 13;
		if (*arg == ' ') {
			arg++;
			while (*arg == ' ') {
				arg++;
			}
		}

		if (*arg) {
			if (!strcmp (arg, "on") || !strcmp (arg, "1") || !strcmp (arg, "true")) {
				r2sym_merge_set_enabled (1);
			} else if (!strcmp (arg, "off") || !strcmp (arg, "0") || !strcmp (arg, "false")) {
				r2sym_merge_set_enabled (0);
			} else if (cons) {
				r_cons_println (cons, "Usage: a:sla.sym.merge [on|off]");
				return true;
			}
		} else {
			int enabled = r2sym_merge_is_enabled ();
			r2sym_merge_set_enabled (!enabled);
		}

		if (cons) {
			r_cons_printf (cons, "sym merge: %s\n", r2sym_merge_is_enabled () ? "on" : "off");
		}
		return true;
	}

	if (!strcmp (cmd, "sla.sym") || !strcmp (cmd, "sla.sym.paths")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Call symbolic execution */
		char *result;
		if (!strcmp (cmd, "sla.sym.paths")) {
			result = r2sym_paths (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);
		} else {
			result = r2sym_function (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);
		}

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strcmp (cmd, "sla.taint")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		char *result = r2taint_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strcmp (cmd, "sla.dec")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Decompile */
		char *result = r2dec_function (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, fcn->name);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	if (!strcmp (cmd, "sla.cfg") || !strcmp (cmd, "sla.cfg.json")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return true;
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return true;
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return true;
		}

		/* Generate CFG */
		char *result;
		if (!strcmp (cmd, "sla.cfg.json")) {
			result = r2cfg_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);
		} else {
			result = r2cfg_function_ascii (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);
		}

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return true;
	}

	R_LOG_ERROR ("Unknown subcommand. See 'a:sla?' for help");
	return true;
}

RAnalPlugin r_anal_plugin_sleigh = {
	.meta = {
		.name = "sla",
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
