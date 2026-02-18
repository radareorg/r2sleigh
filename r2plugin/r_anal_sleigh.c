/* radare2 - LGPL - Copyright 2025 - r2sleigh project */

#include <r_anal.h>
#include <r_core.h>
#include <r_lib.h>
#include <r_version.h>
#include <r_util/r_json.h>
#include <r_util/r_num.h>
#include <r_util/r_str.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

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
extern void r2il_block_set_switch_info(R2ILBlock *block, unsigned long long switch_addr,
    unsigned long long min_val, unsigned long long max_val, unsigned long long default_target,
    const unsigned long long *case_values, const unsigned long long *case_targets, size_t num_cases);

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
extern char *r2il_block_op_json_named(const R2ILContext *ctx, const R2ILBlock *block, size_t index);
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
extern char *r2taint_function_summary_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2taint_sources_sinks_json(const char *json);

/* Symbolic execution */
extern char *r2sym_function(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long entry_addr);
extern char *r2sym_paths(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long entry_addr);
extern char *r2sym_explore_to(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks,
	unsigned long long entry_addr, unsigned long long target_addr);
extern char *r2sym_solve_to(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks,
	unsigned long long entry_addr, unsigned long long target_addr);
extern int r2sym_set_symbol_map_json(const char *json);
extern int r2sym_merge_is_enabled(void);
extern void r2sym_merge_set_enabled(int enabled);

/* Decompiler */
extern char *r2dec_function(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, const char *func_name);
extern char *r2dec_function_with_context(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks,
                                          const char *func_name, const char *func_names_json,
                                          const char *strings_json, const char *symbols_json,
                                          const char *signature_json, const char *stack_vars_json,
                                          const char *types_json);

/* CFG */
extern char *r2cfg_function_ascii(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2cfg_function_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks);
extern char *r2il_get_reg_profile(const R2ILContext *ctx);

/* radare2 Deep Integration */
extern int r2sleigh_analyze_fcn(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long fcn_addr);
extern char *r2sleigh_analyze_fcn_annotations(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long fcn_addr);
extern char *r2sleigh_recover_vars(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long fcn_addr);
extern char *r2sleigh_get_data_refs(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks, unsigned long long fcn_addr);
extern char *r2sleigh_infer_signature_cc_json(const R2ILContext *ctx, const R2ILBlock **blocks, size_t num_blocks,
	unsigned long long fcn_addr, const char *fcn_name);
/* Per-architecture context (lazy init)
 *
 * WARNING: These globals are NOT thread-safe. This plugin assumes
 * single-threaded radare2 usage. If radare2 becomes multi-threaded,
 * this code must be updated with proper synchronization (e.g., mutex).
 */
static R2ILContext *sleigh_ctx = NULL;
static char *sleigh_arch = NULL;
static char *sleigh_arch_override = NULL;

typedef struct {
	bool has_state;
	char *mode;
	ut64 function_addr;
	ut64 entry_addr;
	ut64 target_addr;
	char *result_json;
} SymStateCache;

static SymStateCache sym_state_cache = {0};
static bool sleigh_pdd_core_plugin_registered = false;
static RCore *sleigh_pdd_core_plugin_core = NULL;

/* Minimum bytes to pass to libsla (it reads ahead for variable-length instructions) */
#define SLEIGH_MIN_BYTES 16
#define SLEIGH_BLOCK_MAX_BYTES 256
#define SLEIGH_TAINT_MAX_BLOCKS 200
#define SLEIGH_SIG_WRITEBACK_MAX_BLOCKS 200
#define SLEIGH_SIG_MIN_CONFIDENCE 70
#define SLEIGH_CC_MIN_CONFIDENCE 80
#define SLEIGH_CALLER_PROP_MAX_CALLEES 128
#define SLEIGH_CALLER_PROP_MAX_CALLERS_PER_CALLEE 32
#define SLEIGH_CALLER_PROP_MAX_CALLERS_TOTAL 256
#define SLEIGH_CALLER_PROP_SAMPLE_MAX 5
#define SLEIGH_TAINT_LABEL_MAX 6
#define SLEIGH_COMMENT_PREFIX_TAINT "sla.taint:"
#define SLEIGH_COMMENT_PREFIX_TAINT_RISK "sla.taint.risk:"

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

static void sym_state_cache_clear(void) {
	free (sym_state_cache.mode);
	free (sym_state_cache.result_json);
	sym_state_cache.mode = NULL;
	sym_state_cache.result_json = NULL;
	sym_state_cache.function_addr = 0;
	sym_state_cache.entry_addr = 0;
	sym_state_cache.target_addr = 0;
	sym_state_cache.has_state = false;
}

static void sym_state_cache_update(const char *mode, ut64 function_addr, ut64 entry_addr, ut64 target_addr, const char *result_json) {
	if (!mode || !result_json || !*result_json) {
		return;
	}
	sym_state_cache_clear ();
	sym_state_cache.mode = strdup (mode);
	sym_state_cache.result_json = strdup (result_json);
	if (!sym_state_cache.mode || !sym_state_cache.result_json) {
		sym_state_cache_clear ();
		return;
	}
	sym_state_cache.function_addr = function_addr;
	sym_state_cache.entry_addr = entry_addr;
	sym_state_cache.target_addr = target_addr;
	sym_state_cache.has_state = true;
}

static bool sym_result_has_error(const char *json) {
	char *json_copy;
	RJson *root;
	const RJson *error_field;
	bool has_error;

	if (!json || !*json) {
		return true;
	}
	json_copy = strdup (json);
	if (!json_copy) {
		return true;
	}
	root = r_json_parse (json_copy);
	free (json_copy);
	if (!root) {
		return true;
	}
	has_error = false;
	if (root->type == R_JSON_OBJECT) {
		error_field = r_json_get (root, "error");
		if (error_field && error_field->type == R_JSON_STRING && error_field->str_value && *error_field->str_value) {
			has_error = true;
		}
	}
	r_json_free (root);
	return has_error;
}

static char *sym_state_cache_to_json(void) {
	int needed;
	char *json;

	if (!sym_state_cache.has_state || !sym_state_cache.result_json) {
		return strdup ("{\"has_state\":false}");
	}
	needed = snprintf (NULL, 0,
		"{\"has_state\":true,\"mode\":\"%s\",\"entry\":\"0x%"PFMT64x"\",\"target\":\"0x%"PFMT64x"\",\"function\":\"0x%"PFMT64x"\",\"result\":%s}",
		sym_state_cache.mode ? sym_state_cache.mode : "",
		sym_state_cache.entry_addr,
		sym_state_cache.target_addr,
		sym_state_cache.function_addr,
		sym_state_cache.result_json);
	if (needed < 0) {
		return strdup ("{\"has_state\":false}");
	}
	json = malloc ((size_t)needed + 1);
	if (!json) {
		return strdup ("{\"has_state\":false}");
	}
	snprintf (json, (size_t)needed + 1,
		"{\"has_state\":true,\"mode\":\"%s\",\"entry\":\"0x%"PFMT64x"\",\"target\":\"0x%"PFMT64x"\",\"function\":\"0x%"PFMT64x"\",\"result\":%s}",
		sym_state_cache.mode ? sym_state_cache.mode : "",
		sym_state_cache.entry_addr,
		sym_state_cache.target_addr,
		sym_state_cache.function_addr,
		sym_state_cache.result_json);
	return json;
}

static const char *skip_cmd_spaces(const char *s) {
	while (s && *s == ' ') {
		s++;
	}
	return s;
}

static bool sleigh_parse_pdd_alias(const char *input, const char **alias_name, const char **suffix) {
	if (!input || !alias_name || !suffix) {
		return false;
	}
	if (r_str_startswith (input, "pdd")) {
		*alias_name = "pdd";
		*suffix = input + 3;
		return true;
	}
	if (r_str_startswith (input, "pdD")) {
		*alias_name = "pdD";
		*suffix = input + 3;
		return true;
	}
	return false;
}

static bool sleigh_pdd_core_cmd(RCorePluginSession *cps, const char *input) {
	const char *alias_name = NULL;
	const char *suffix = NULL;
	const char *target_arg = NULL;
	char *anal_cmd = NULL;
	char *res;
	RCore *core;

	if (!cps || !input) {
		return false;
	}
	core = cps->core;
	if (!core || !core->anal) {
		return false;
	}
	if (!sleigh_parse_pdd_alias (input, &alias_name, &suffix)) {
		return false;
	}

	if (*suffix == '\0') {
		target_arg = NULL;
	} else if (*suffix == '?') {
		if (suffix[1] != '\0') {
			return false;
		}
		if (core->cons) {
			r_cons_println (core->cons, "| pdd [name|addr] - Alias for a:sla.dec [name|addr]");
			r_cons_println (core->cons, "| pdD [name|addr] - Alias for a:sla.dec [name|addr]");
		}
		return true;
	} else if (*suffix == ' ') {
		suffix = skip_cmd_spaces (suffix);
		if (!*suffix) {
			target_arg = NULL;
		} else if (*suffix == '?' && suffix[1] == '\0') {
			if (core->cons) {
				r_cons_println (core->cons, "| pdd [name|addr] - Alias for a:sla.dec [name|addr]");
				r_cons_println (core->cons, "| pdD [name|addr] - Alias for a:sla.dec [name|addr]");
			}
			return true;
		} else {
			target_arg = suffix;
		}
	} else {
		return false;
	}

	if (target_arg && *target_arg) {
		anal_cmd = r_str_newf ("sla.dec %s", target_arg);
	} else {
		anal_cmd = strdup ("sla.dec");
	}
	if (!anal_cmd) {
		R_LOG_ERROR ("r2sleigh: failed to allocate %s alias command", alias_name);
		return false;
	}

	res = r_anal_cmd (core->anal, anal_cmd);
	free (anal_cmd);
	if (res) {
		free (res);
		return true;
	}
	return false;
}

static RCorePlugin r_core_plugin_sleigh_pdd = {
	.meta = {
		.name = "sleigh.pdd",
		.desc = "r2sleigh transparent pdd/pdD alias",
		.license = "LGPL3",
		.author = "r2sleigh project",
	},
	.call = sleigh_pdd_core_cmd,
};

static void ensure_sleigh_pdd_core_plugin(RAnal *anal) {
	RCore *core;

	if (sleigh_pdd_core_plugin_registered || !anal) {
		return;
	}
	core = anal->coreb.core;
	if (!core || !core->rcmd) {
		return;
	}
	if (r_core_plugin_add (core->rcmd, &r_core_plugin_sleigh_pdd)) {
		sleigh_pdd_core_plugin_registered = true;
		sleigh_pdd_core_plugin_core = core;
	}
}

static void cleanup_sleigh_pdd_core_plugin(void) {
	if (!sleigh_pdd_core_plugin_registered) {
		return;
	}
	if (sleigh_pdd_core_plugin_core && sleigh_pdd_core_plugin_core->rcmd) {
		(void)r_core_plugin_remove (sleigh_pdd_core_plugin_core->rcmd, &r_core_plugin_sleigh_pdd);
	}
	sleigh_pdd_core_plugin_registered = false;
	sleigh_pdd_core_plugin_core = NULL;
}

static bool parse_sym_target_expr(RCore *core, const char *expr, ut64 *target) {
	if (!core || !core->num || !expr || !*expr || !target) {
		return false;
	}
	if (!r_num_is_valid_input (core->num, expr)) {
		return false;
	}
	*target = r_num_math (core->num, expr);
	return true;
}

static char *build_sym_symbol_map_json(RCore *core) {
	if (!core) {
		return strdup ("{}");
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return strdup ("{}");
	}
	pj_o (pj);

	/* aflj: [{addr:0x...,name:"..."}] */
	char *aflj = r_core_cmd_str (core, "aflj");
	if (aflj && aflj[0] == '[') {
		RJson *root = r_json_parse (aflj);
		if (root && root->type == R_JSON_ARRAY) {
			RJson *elem;
			for (elem = root->children.first; elem; elem = elem->next) {
				if (elem->type != R_JSON_OBJECT) {
					continue;
				}
				const RJson *addr = r_json_get (elem, "addr");
				const RJson *name = r_json_get (elem, "name");
				if (addr && name && addr->type == R_JSON_INTEGER && name->type == R_JSON_STRING && name->str_value) {
					char key[32];
					snprintf (key, sizeof (key), "0x%llx", (unsigned long long)addr->num.u_value);
					pj_ks (pj, key, name->str_value);
				}
			}
			r_json_free (root);
		}
	}
	free (aflj);

	/* fs *;fj: include import/plt flags such as sym.imp.memcpy */
	char *fj = r_core_cmd_str (core, "fs *;fj");
	if (fj && fj[0] == '[') {
		RJson *root = r_json_parse (fj);
		if (root && root->type == R_JSON_ARRAY) {
			RJson *elem;
			for (elem = root->children.first; elem; elem = elem->next) {
				if (elem->type != R_JSON_OBJECT) {
					continue;
				}
				const RJson *addr = r_json_get (elem, "addr");
				const RJson *name = r_json_get (elem, "name");
				if (addr && name && addr->type == R_JSON_INTEGER && name->type == R_JSON_STRING && name->str_value) {
					char key[32];
					snprintf (key, sizeof (key), "0x%llx", (unsigned long long)addr->num.u_value);
					pj_ks (pj, key, name->str_value);
				}
			}
			r_json_free (root);
		}
	}
	free (fj);

	pj_end (pj);
	return pj_drain (pj);
}

static bool ssa_var_to_reg_name(const char *ssa_name, char *out, size_t out_size) {
	if (!ssa_name || !out || out_size == 0) {
		return false;
	}

	const char *suffix = strrchr (ssa_name, '_');
	size_t len = suffix ? (size_t)(suffix - ssa_name) : strlen (ssa_name);
	if (len == 0 || len >= out_size) {
		return false;
	}

	char base[128];
	if (len >= sizeof (base)) {
		return false;
	}
	memcpy (base, ssa_name, len);
	base[len] = '\0';

	if (r_str_startswith (base, "const:") ||
		r_str_startswith (base, "tmp:") ||
		r_str_startswith (base, "ram:") ||
		r_str_startswith (base, "space")) {
		return false;
	}

	const char *name = base;
	if (r_str_startswith (base, "reg:")) {
		name = base + 4;
	}

	r_str_ncpy (out, name, out_size);
	return out[0] != '\0';
}

static bool vec_has_reg(const RVecRArchValue *vec, const char *reg_name) {
	size_t len;
	size_t i;

	if (!vec || !reg_name) {
		return false;
	}

	len = RVecRArchValue_length (vec);
	for (i = 0; i < len; i++) {
		RArchValue *value = RVecRArchValue_at (vec, i);
		if (value && value->reg && !strcmp (value->reg, reg_name)) {
			return true;
		}
	}

	return false;
}

static void add_ssa_reg_values(RAnal *anal, const RJson *array, RVecRArchValue *vec, int access) {
	size_t i;

	if (!anal || !array || array->type != R_JSON_ARRAY || !vec) {
		return;
	}

	for (i = 0; i < array->children.count; i++) {
		const RJson *item = r_json_item (array, i);
		if (!item || item->type != R_JSON_STRING || !item->str_value) {
			continue;
		}

		char regbuf[64];
		if (!ssa_var_to_reg_name (item->str_value, regbuf, sizeof (regbuf))) {
			continue;
		}

		RRegItem *reg = r_reg_get (anal->reg, regbuf, -1);
		if (!reg) {
			char alt[64];
			r_str_ncpy (alt, regbuf, sizeof (alt));
			r_str_case (alt, false);
			reg = r_reg_get (anal->reg, alt, -1);
		}
		if (!reg) {
			char alt[64];
			r_str_ncpy (alt, regbuf, sizeof (alt));
			r_str_case (alt, true);
			reg = r_reg_get (anal->reg, alt, -1);
		}
		if (!reg || !reg->name || vec_has_reg (vec, reg->name)) {
			continue;
		}

		RArchValue value = {0};
		value.type = R_ANAL_VAL_REG;
		value.reg = reg->name;
		value.access = access;
		RVecRArchValue_push_back (vec, &value);
	}
}

static void add_memory_archvalue(RAnal *anal, const RJson *mem_access, RVecRArchValue *vec, int access) {
	if (!anal || !mem_access || mem_access->type != R_JSON_OBJECT || !vec) {
		return;
	}

	const RJson *type = r_json_get (mem_access, "type");
	const RJson *size = r_json_get (mem_access, "size");
	const RJson *addr = r_json_get (mem_access, "addr_detail");
	if (!addr || addr->type != R_JSON_OBJECT) {
		const RJson *addr_alt = r_json_get (mem_access, "addr");
		if (addr_alt && addr_alt->type == R_JSON_OBJECT) {
			addr = addr_alt;
		}
	}

	if (!type || !type->str_value || !size) {
		return;
	}

	RArchValue value = {0};
	value.type = R_ANAL_VAL_MEM;
	value.access = access;

	// Set memory size and reference
	value.memref = (size->type == R_JSON_INTEGER) ? size->num.u_value : 1;

	// Parse address information
	if (addr && addr->type == R_JSON_OBJECT) {
		const RJson *addr_space = r_json_get (addr, "space");
		const RJson *addr_offset = r_json_get (addr, "offset");
		const RJson *addr_name = r_json_get (addr, "name");

		if (addr_space && addr_space->str_value &&
			r_str_casecmp (addr_space->str_value, "register") == 0 &&
			addr_name && addr_name->str_value) {
			// Register-based memory access
			RRegItem *reg = r_reg_get (anal->reg, addr_name->str_value, -1);
			if (!reg) {
				char alt[64];
				r_str_ncpy (alt, addr_name->str_value, sizeof (alt));
				r_str_case (alt, false);
				reg = r_reg_get (anal->reg, alt, -1);
			}
			if (!reg) {
				char alt[64];
				r_str_ncpy (alt, addr_name->str_value, sizeof (alt));
				r_str_case (alt, true);
				reg = r_reg_get (anal->reg, alt, -1);
			}
			if (reg && reg->name) {
				value.reg = reg->name;
			}
			value.base = 0; // Will be calculated by radare2 from register
			value.delta = (addr_offset && addr_offset->type == R_JSON_INTEGER) ? addr_offset->num.s_value : 0;
		} else if (addr_offset && addr_offset->type == R_JSON_INTEGER) {
			// Absolute memory access
			value.reg = NULL;
			value.base = addr_offset->num.u_value;
			value.delta = 0;
		}
	}

	if (!value.reg) {
		const RJson *stack_base = r_json_get (mem_access, "stack_base");
		const RJson *stack_offset = r_json_get (mem_access, "stack_offset");
		if (stack_base && stack_base->str_value) {
			RRegItem *reg = r_reg_get (anal->reg, stack_base->str_value, -1);
			if (!reg) {
				char alt[64];
				r_str_ncpy (alt, stack_base->str_value, sizeof (alt));
				r_str_case (alt, false);
				reg = r_reg_get (anal->reg, alt, -1);
			}
			if (!reg) {
				char alt[64];
				r_str_ncpy (alt, stack_base->str_value, sizeof (alt));
				r_str_case (alt, true);
				reg = r_reg_get (anal->reg, alt, -1);
			}
			if (reg && reg->name) {
				value.reg = reg->name;
				value.base = 0;
				value.delta = (stack_offset && stack_offset->type == R_JSON_INTEGER)
					? stack_offset->num.s_value
					: 0;
			}
		}
	}

	RVecRArchValue_push_back (vec, &value);
}

static void add_immediate_archvalue(const RJson *varnode, RVecRArchValue *vec, int access) {
	if (!varnode || varnode->type != R_JSON_OBJECT || !vec) {
		return;
	}

	const RJson *space = r_json_get (varnode, "space");
	const RJson *offset = r_json_get (varnode, "offset");

	if (!space || !space->str_value || !offset) {
		return;
	}

	// Only create immediate values for constant space
	if (r_str_casecmp (space->str_value, "const") != 0) {
		return;
	}

	RArchValue value = {0};
	value.type = R_ANAL_VAL_IMM;
	value.access = access;
	value.imm = (offset->type == R_JSON_INTEGER) ? offset->num.s_value : 0;

	RVecRArchValue_push_back (vec, &value);
}

static void fill_op_values_enhanced(RAnal *anal, RAnalOp *op, R2ILContext *ctx, const R2ILBlock *block) {
	if (!anal || !op || !ctx || !block) {
		return;
	}

	// Get memory accesses
	char *mem_json = r2il_block_mem_access (ctx, block);
	if (mem_json) {
		RJson *mem_root = r_json_parse (mem_json);
		if (mem_root && mem_root->type == R_JSON_ARRAY) {
			size_t i;
			for (i = 0; i < mem_root->children.count; i++) {
				const RJson *mem_access = r_json_item (mem_root, i);
				if (mem_access) {
					const RJson *type = r_json_get (mem_access, "type");
					if (type && type->str_value) {
						int access = R_PERM_R;
						bool is_store = !strcmp (type->str_value, "store");
						if (is_store) {
							access = R_PERM_W;
						}
						add_memory_archvalue (anal, mem_access, is_store ? &op->dsts : &op->srcs, access);
					}
				}
			}
		}
		r_json_free (mem_root);
		r2il_string_free (mem_json);
	}

	// Get all varnodes to find immediate values
	char *vars_json = r2il_block_varnodes (ctx, block);
	if (vars_json) {
		RJson *vars_root = r_json_parse (vars_json);
		if (vars_root && vars_root->type == R_JSON_ARRAY) {
			size_t i;
			for (i = 0; i < vars_root->children.count; i++) {
				const RJson *varnode = r_json_item (vars_root, i);
				if (varnode) {
					add_immediate_archvalue (varnode, &op->srcs, R_PERM_R);
				}
			}
		}
		r_json_free (vars_root);
		r2il_string_free (vars_json);
	}

	// Still add SSA register values for def-use analysis
	char *defuse_json = r2il_block_defuse_json (ctx, block);
	if (defuse_json) {
		RJson *root = r_json_parse (defuse_json);
		if (root && root->type == R_JSON_OBJECT) {
			const RJson *inputs = r_json_get (root, "inputs");
			const RJson *outputs = r_json_get (root, "outputs");
			add_ssa_reg_values (anal, inputs, &op->srcs, R_PERM_R);
			add_ssa_reg_values (anal, outputs, &op->dsts, R_PERM_W);
		}
		r_json_free (root);
		r2il_string_free (defuse_json);
	}
}

static void analyze_stack_operation(R2ILContext *ctx, const R2ILBlock *block, RAnalOp *op) {
	if (!ctx || !block || !op) {
		return;
	}

	// Get memory accesses to identify stack operations
	char *mem_json = r2il_block_mem_access (ctx, block);
	if (!mem_json) {
		return;
	}

	RJson *mem_root = r_json_parse (mem_json);
	if (!mem_root || mem_root->type != R_JSON_ARRAY) {
		r_json_free (mem_root);
		r2il_string_free (mem_json);
		return;
	}

	// Look for stack operations
	size_t i;
	for (i = 0; i < mem_root->children.count; i++) {
		const RJson *mem_access = r_json_item (mem_root, i);
		if (!mem_access) continue;

		const RJson *stack = r_json_get (mem_access, "stack");
		const RJson *stack_offset = r_json_get (mem_access, "stack_offset");
		const RJson *type = r_json_get (mem_access, "type");

		if (stack && stack->type == R_JSON_BOOLEAN && stack->num.u_value) {
			// This is a stack operation
			if (type && type->str_value) {
				if (strcmp (type->str_value, "store") == 0) {
					op->stackop = R_ANAL_STACK_SET;
				} else if (strcmp (type->str_value, "load") == 0) {
					op->stackop = R_ANAL_STACK_GET;
				}
			}

			// Set stack pointer offset
			if (stack_offset && stack_offset->type == R_JSON_INTEGER) {
				op->stackptr = stack_offset->num.s_value;
			}

			break; // Only handle first stack operation for now
		}
	}

	r_json_free (mem_root);
	r2il_string_free (mem_json);
}

static void set_operation_direction(R2ILContext *ctx, const R2ILBlock *block, RAnalOp *op) {
	if (!ctx || !block || !op) {
		return;
	}

	// Get memory accesses to determine direction
	char *mem_json = r2il_block_mem_access (ctx, block);
	if (!mem_json) {
		return;
	}

	RJson *mem_root = r_json_parse (mem_json);
	if (!mem_root || mem_root->type != R_JSON_ARRAY) {
		r_json_free (mem_root);
		r2il_string_free (mem_json);
		return;
	}

	op->direction = 0; // Default: no specific direction

	size_t i;
	for (i = 0; i < mem_root->children.count; i++) {
		const RJson *mem_access = r_json_item (mem_root, i);
		if (!mem_access) continue;

		const RJson *type = r_json_get (mem_access, "type");
		if (type && type->str_value) {
			if (strcmp (type->str_value, "store") == 0) {
				op->direction |= R_ANAL_OP_DIR_WRITE;
			} else if (strcmp (type->str_value, "load") == 0) {
				op->direction |= R_ANAL_OP_DIR_READ;
			}
		}
	}

	// If no memory operations, default to read
	if (op->direction == 0) {
		op->direction = R_ANAL_OP_DIR_READ;
	}

	r_json_free (mem_root);
	r2il_string_free (mem_json);
}

static void print_reg_values_json(RCons *cons, const RVecRArchValue *vec) {
	size_t len;
	size_t i;
	bool first = true;

	if (!cons || !vec) {
		return;
	}

	len = RVecRArchValue_length (vec);
	for (i = 0; i < len; i++) {
		const RArchValue *value = RVecRArchValue_at (vec, i);
		if (!value || value->type != R_ANAL_VAL_REG || !value->reg) {
			continue;
		}

		if (!first) {
			r_cons_print (cons, ",");
		}
		r_cons_printf (cons, "\"%s\"", value->reg);
		first = false;
	}
}

typedef struct {
	char *label;
	ut64 *blocks;
	size_t count;
	size_t capacity;
} TaintLabelSource;

typedef struct {
	TaintLabelSource *items;
	size_t count;
	size_t capacity;
} TaintSourceMap;

typedef struct {
	ut64 addr;
	int hits;
	int call_hits;
	int store_hits;
	char **call_names;
	size_t ncall_names;
	size_t call_name_cap;
	char **labels;
	size_t nlabels;
	size_t label_cap;
} TaintBlockSummary;

typedef struct {
	TaintBlockSummary *items;
	size_t count;
	size_t capacity;
} TaintSummaryMap;

typedef struct {
	ut64 from;
	ut64 to;
} EdgePair;

typedef struct {
	EdgePair *items;
	size_t count;
	size_t capacity;
} EdgeSet;

typedef struct {
	ut64 *updated_callers;
	size_t updated_callers_count;
	size_t updated_callers_capacity;
	char **sample_callees;
	size_t sample_callees_count;
	size_t sample_callees_capacity;
	int prop_callees_triggered;
	int prop_callees_skipped_cap;
	int prop_callers_considered;
	int prop_callers_updated;
	int prop_callers_dedup_skipped;
	int prop_callers_missing_fcn;
	int prop_callers_per_callee_cap_skipped;
	int prop_callers_total_cap_skipped;
	int prop_type_match_failures;
	int prop_afva_failures;
} CallerPropagationState;

static bool append_unique_ut64(ut64 **items, size_t *count, size_t *capacity, ut64 value) {
	size_t i;
	ut64 *next;

	if (!items || !count || !capacity) {
		return false;
	}

	for (i = 0; i < *count; i++) {
		if ((*items)[i] == value) {
			return true;
		}
	}

	if (*count >= *capacity) {
		size_t new_capacity = *capacity ? (*capacity * 2) : 4;
		next = realloc (*items, new_capacity * sizeof (ut64));
		if (!next) {
			return false;
		}
		*items = next;
		*capacity = new_capacity;
	}

	(*items)[(*count)++] = value;
	return true;
}

static bool append_unique_string(char ***items, size_t *count, size_t *capacity, const char *value) {
	size_t i;
	char **next;
	char *dup;

	if (!items || !count || !capacity || !value || !*value) {
		return false;
	}

	for (i = 0; i < *count; i++) {
		if (!strcmp ((*items)[i], value)) {
			return true;
		}
	}

	if (*count >= *capacity) {
		size_t new_capacity = *capacity ? (*capacity * 2) : 4;
		next = realloc (*items, new_capacity * sizeof (char *));
		if (!next) {
			return false;
		}
		*items = next;
		*capacity = new_capacity;
	}

	dup = strdup (value);
	if (!dup) {
		return false;
	}
	(*items)[(*count)++] = dup;
	return true;
}

static void free_string_array(char **items, size_t count) {
	size_t i;
	if (!items) {
		return;
	}
	for (i = 0; i < count; i++) {
		free (items[i]);
	}
	free (items);
}

static void caller_propagation_state_init(CallerPropagationState *state) {
	if (!state) {
		return;
	}
	memset (state, 0, sizeof (*state));
}

static void caller_propagation_state_fini(CallerPropagationState *state) {
	if (!state) {
		return;
	}
	free (state->updated_callers);
	free_string_array (state->sample_callees, state->sample_callees_count);
	memset (state, 0, sizeof (*state));
}

static bool ut64_array_contains(const ut64 *items, size_t count, ut64 value) {
	size_t i;
	for (i = 0; i < count; i++) {
		if (items[i] == value) {
			return true;
		}
	}
	return false;
}

static void taint_source_map_init(TaintSourceMap *map) {
	if (!map) {
		return;
	}
	map->items = NULL;
	map->count = 0;
	map->capacity = 0;
}

static void taint_source_map_free(TaintSourceMap *map) {
	size_t i;
	if (!map) {
		return;
	}
	for (i = 0; i < map->count; i++) {
		free (map->items[i].label);
		free (map->items[i].blocks);
	}
	free (map->items);
	map->items = NULL;
	map->count = 0;
	map->capacity = 0;
}

static TaintLabelSource *taint_source_map_get_or_add(TaintSourceMap *map, const char *label) {
	size_t i;
	TaintLabelSource *next;

	if (!map || !label || !*label) {
		return NULL;
	}

	for (i = 0; i < map->count; i++) {
		if (!strcmp (map->items[i].label, label)) {
			return &map->items[i];
		}
	}

	if (map->count >= map->capacity) {
		size_t new_capacity = map->capacity ? (map->capacity * 2) : 8;
		next = realloc (map->items, new_capacity * sizeof (TaintLabelSource));
		if (!next) {
			return NULL;
		}
		map->items = next;
		map->capacity = new_capacity;
	}

	map->items[map->count].label = strdup (label);
	map->items[map->count].blocks = NULL;
	map->items[map->count].count = 0;
	map->items[map->count].capacity = 0;
	if (!map->items[map->count].label) {
		return NULL;
	}
	return &map->items[map->count++];
}

static const TaintLabelSource *taint_source_map_find(const TaintSourceMap *map, const char *label) {
	size_t i;
	if (!map || !label || !*label) {
		return NULL;
	}
	for (i = 0; i < map->count; i++) {
		if (!strcmp (map->items[i].label, label)) {
			return &map->items[i];
		}
	}
	return NULL;
}

static bool taint_source_map_add(TaintSourceMap *map, const char *label, ut64 block_addr) {
	TaintLabelSource *entry = taint_source_map_get_or_add (map, label);
	if (!entry) {
		return false;
	}
	return append_unique_ut64 (&entry->blocks, &entry->count, &entry->capacity, block_addr);
}

static void taint_summary_map_init(TaintSummaryMap *map) {
	if (!map) {
		return;
	}
	map->items = NULL;
	map->count = 0;
	map->capacity = 0;
}

static void taint_summary_map_free(TaintSummaryMap *map) {
	size_t i;
	if (!map) {
		return;
	}
	for (i = 0; i < map->count; i++) {
		free_string_array (map->items[i].call_names, map->items[i].ncall_names);
		free_string_array (map->items[i].labels, map->items[i].nlabels);
	}
	free (map->items);
	map->items = NULL;
	map->count = 0;
	map->capacity = 0;
}

static TaintBlockSummary *taint_summary_map_get_or_add(TaintSummaryMap *map, ut64 addr) {
	size_t i;
	TaintBlockSummary *next;

	if (!map) {
		return NULL;
	}
	for (i = 0; i < map->count; i++) {
		if (map->items[i].addr == addr) {
			return &map->items[i];
		}
	}

	if (map->count >= map->capacity) {
		size_t new_capacity = map->capacity ? (map->capacity * 2) : 8;
		next = realloc (map->items, new_capacity * sizeof (TaintBlockSummary));
		if (!next) {
			return NULL;
		}
		map->items = next;
		map->capacity = new_capacity;
	}

	map->items[map->count].addr = addr;
	map->items[map->count].hits = 0;
	map->items[map->count].call_hits = 0;
	map->items[map->count].store_hits = 0;
	map->items[map->count].call_names = NULL;
	map->items[map->count].ncall_names = 0;
	map->items[map->count].call_name_cap = 0;
	map->items[map->count].labels = NULL;
	map->items[map->count].nlabels = 0;
	map->items[map->count].label_cap = 0;
	return &map->items[map->count++];
}

static bool taint_summary_add_label(TaintBlockSummary *summary, const char *label) {
	if (!summary) {
		return false;
	}
	return append_unique_string (&summary->labels, &summary->nlabels, &summary->label_cap, label);
}

static bool taint_summary_add_call_name(TaintBlockSummary *summary, const char *name) {
	if (!summary) {
		return false;
	}
	return append_unique_string (&summary->call_names, &summary->ncall_names, &summary->call_name_cap, name);
}

typedef enum {
	TAINT_RISK_NONE = 0,
	TAINT_RISK_LOW,
	TAINT_RISK_MEDIUM,
	TAINT_RISK_HIGH,
	TAINT_RISK_CRITICAL,
} TaintRiskLevel;

static const char *taint_risk_level_name(TaintRiskLevel level) {
	switch (level) {
	case TAINT_RISK_CRITICAL:
		return "CRITICAL";
	case TAINT_RISK_HIGH:
		return "HIGH";
	case TAINT_RISK_MEDIUM:
		return "MEDIUM";
	case TAINT_RISK_LOW:
		return "LOW";
	case TAINT_RISK_NONE:
	default:
		return "NONE";
	}
}

static const char *taint_risk_level_flag_name(TaintRiskLevel level) {
	switch (level) {
	case TAINT_RISK_CRITICAL:
		return "critical";
	case TAINT_RISK_HIGH:
		return "high";
	case TAINT_RISK_MEDIUM:
		return "medium";
	case TAINT_RISK_LOW:
		return "low";
	case TAINT_RISK_NONE:
	default:
		return "none";
	}
}

static const char *dangerous_sinks[] = {
	"memcpy",
	"strcpy",
	"strcat",
	"gets",
	"sprintf",
	"snprintf",
	"system",
	"execve",
	"execl",
	"popen",
	"read",
	"recv",
	"recvfrom",
	"scanf",
	"fscanf",
};

static int cmp_strings_lex(const void *a, const void *b) {
	const char *sa = *(const char * const *)a;
	const char *sb = *(const char * const *)b;
	return strcmp (sa ? sa : "", sb ? sb : "");
}

static bool parse_ssa_target_addr(const char *src, ut64 *out) {
	char buf[128];
	const char *payload;
	const char *end;
	size_t len;
	char *tail = NULL;
	unsigned long long value;

	if (!src || !out) {
		return false;
	}

	if (r_str_startswith (src, "const:")) {
		payload = src + 6;
	} else if (r_str_startswith (src, "ram:")) {
		payload = src + 4;
	} else {
		return false;
	}

	end = strchr (payload, '_');
	len = end ? (size_t)(end - payload) : strlen (payload);
	if (!len || len >= sizeof (buf)) {
		return false;
	}
	memcpy (buf, payload, len);
	buf[len] = '\0';

	errno = 0;
	value = strtoull (buf, &tail, 16);
	if (errno != 0 || !tail || *tail != '\0') {
		return false;
	}

	*out = (ut64)value;
	return true;
}

static void trim_call_prefixes(char *name) {
	static const char *prefixes[] = {"sym.imp.", "sym.", "dbg.", "imp.", "reloc."};
	bool changed = true;
	size_t i;

	if (!name || !*name) {
		return;
	}

	while (changed) {
		changed = false;
		for (i = 0; i < R_ARRAY_SIZE (prefixes); i++) {
			size_t plen = strlen (prefixes[i]);
			if (r_str_startswith (name, prefixes[i])) {
				memmove (name, name + plen, strlen (name + plen) + 1);
				changed = true;
			}
		}
	}
}

static char *clean_call_name(const char *raw) {
	char *name;
	char *at;
	size_t len;

	if (!raw || !*raw) {
		return NULL;
	}

	name = strdup (raw);
	if (!name) {
		return NULL;
	}

	trim_call_prefixes (name);

	len = strlen (name);
	while (len >= 4 && !strcmp (name + len - 4, "@plt")) {
		name[len - 4] = '\0';
		len -= 4;
	}
	while (len >= 4 && !strcmp (name + len - 4, ".plt")) {
		name[len - 4] = '\0';
		len -= 4;
	}

	at = strchr (name, '@');
	if (at) {
		*at = '\0';
	}

	trim_call_prefixes (name);

	if (!*name) {
		free (name);
		return NULL;
	}
	return name;
}

static char *resolve_call_target_name(RCore *core, RAnal *anal, const RJson *hit_op) {
	const RJson *j_sources;
	const RJson *j_src;
	ut64 addr = 0;
	const char *raw_name = NULL;
	char *cleaned = NULL;

	if (!core || !anal || !hit_op || hit_op->type != R_JSON_OBJECT) {
		return NULL;
	}

	j_sources = r_json_get (hit_op, "sources");
	if (!j_sources || j_sources->type != R_JSON_ARRAY) {
		return NULL;
	}
	j_src = j_sources->children.first;
	if (!j_src || j_src->type != R_JSON_STRING || !j_src->str_value) {
		return NULL;
	}
	if (!parse_ssa_target_addr (j_src->str_value, &addr)) {
		return NULL;
	}

	if (core->flags) {
		RFlagItem *flag = r_flag_get_at (core->flags, addr, false);
		if (flag && flag->name && *flag->name) {
			raw_name = flag->name;
		}
	}
	if (!raw_name) {
		RAnalFunction *target_fcn = r_anal_get_fcn_in (anal, addr, R_ANAL_FCN_TYPE_ANY);
		if (target_fcn && target_fcn->name && *target_fcn->name) {
			raw_name = target_fcn->name;
		}
	}
	if (!raw_name) {
		return NULL;
	}

	cleaned = clean_call_name (raw_name);
	return cleaned;
}

static bool is_dangerous_sink(const char *name) {
	size_t i;

	if (!name || !*name) {
		return false;
	}

	for (i = 0; i < R_ARRAY_SIZE (dangerous_sinks); i++) {
		if (!r_str_casecmp (name, dangerous_sinks[i])) {
			return true;
		}
	}
	if (!r_str_ncasecmp (name, "exec", 4)) {
		return true;
	}
	return false;
}

static TaintRiskLevel classify_taint_risk(bool meaningful, bool has_dangerous_call, int call_hits, int store_hits) {
	if (!meaningful) {
		return TAINT_RISK_NONE;
	}
	if (has_dangerous_call) {
		return TAINT_RISK_CRITICAL;
	}
	if (call_hits > 0 && store_hits > 0) {
		return TAINT_RISK_HIGH;
	}
	if (call_hits > 0 || store_hits > 1) {
		return TAINT_RISK_MEDIUM;
	}
	if (store_hits > 0) {
		return TAINT_RISK_LOW;
	}
	return TAINT_RISK_NONE;
}

static void edge_set_init(EdgeSet *set) {
	if (!set) {
		return;
	}
	set->items = NULL;
	set->count = 0;
	set->capacity = 0;
}

static void edge_set_free(EdgeSet *set) {
	if (!set) {
		return;
	}
	free (set->items);
	set->items = NULL;
	set->count = 0;
	set->capacity = 0;
}

static bool edge_set_has(const EdgeSet *set, ut64 from, ut64 to) {
	size_t i;
	if (!set) {
		return false;
	}
	for (i = 0; i < set->count; i++) {
		if (set->items[i].from == from && set->items[i].to == to) {
			return true;
		}
	}
	return false;
}

static bool edge_set_add(EdgeSet *set, ut64 from, ut64 to) {
	EdgePair *next;

	if (!set) {
		return false;
	}
	if (edge_set_has (set, from, to)) {
		return true;
	}

	if (set->count >= set->capacity) {
		size_t new_capacity = set->capacity ? (set->capacity * 2) : 8;
		next = realloc (set->items, new_capacity * sizeof (EdgePair));
		if (!next) {
			return false;
		}
		set->items = next;
		set->capacity = new_capacity;
	}

	set->items[set->count].from = from;
	set->items[set->count].to = to;
	set->count++;
	return true;
}

static bool is_noisy_taint_label(const char *label) {
	if (!label || !*label) {
		return true;
	}

	return !strcmp (label, "input:rsp")
		|| !strcmp (label, "input:rbp")
		|| !strcmp (label, "input:esp")
		|| !strcmp (label, "input:ebp")
		|| !strcmp (label, "input:sp")
		|| !strcmp (label, "input:bp")
		|| !strcmp (label, "input:rip")
		|| !strcmp (label, "input:eip")
		|| !strcmp (label, "input:ip")
		|| r_str_startswith (label, "input:ram:");
}

static int label_rank(const char *label) {
	const char *name = label;
	if (!name) {
		return 1000;
	}
	if (r_str_startswith (name, "input:")) {
		name += 6;
	}

	if (!strcmp (name, "rdi") || !strcmp (name, "edi")) {
		return 0;
	}
	if (!strcmp (name, "rsi") || !strcmp (name, "esi")) {
		return 1;
	}
	if (!strcmp (name, "rdx") || !strcmp (name, "edx")) {
		return 2;
	}
	if (!strcmp (name, "rcx") || !strcmp (name, "ecx")) {
		return 3;
	}
	if (!strcmp (name, "r8") || !strcmp (name, "r8d")) {
		return 4;
	}
	if (!strcmp (name, "r9") || !strcmp (name, "r9d")) {
		return 5;
	}
	if (!strcmp (name, "rax") || !strcmp (name, "eax")) {
		return 10;
	}
	if (!strcmp (name, "rbx") || !strcmp (name, "ebx")) {
		return 11;
	}
	if (!strcmp (name, "r10") || !strcmp (name, "r10d")) {
		return 12;
	}
	if (!strcmp (name, "r11") || !strcmp (name, "r11d")) {
		return 13;
	}
	if (!strcmp (name, "r12") || !strcmp (name, "r12d")) {
		return 14;
	}
	if (!strcmp (name, "r13") || !strcmp (name, "r13d")) {
		return 15;
	}
	if (!strcmp (name, "r14") || !strcmp (name, "r14d")) {
		return 16;
	}
	if (!strcmp (name, "r15") || !strcmp (name, "r15d")) {
		return 17;
	}
	if (r_str_startswith (name, "xmm")) {
		return 40;
	}
	if (r_str_startswith (name, "input:")) {
		return 90;
	}
	return 100;
}

static int cmp_labels_interesting(const void *a, const void *b) {
	const char *la = *(const char * const *)a;
	const char *lb = *(const char * const *)b;
	int ra = label_rank (la);
	int rb = label_rank (lb);

	if (ra < rb) {
		return -1;
	}
	if (ra > rb) {
		return 1;
	}
	return strcmp (la ? la : "", lb ? lb : "");
}

static bool line_has_prefix(const char *line, size_t len, const char *prefix) {
	size_t prefix_len;

	if (!line || !prefix) {
		return false;
	}

	prefix_len = strlen (prefix);
	if (len < prefix_len) {
		return false;
	}
	return !strncmp (line, prefix, prefix_len);
}

static bool is_sla_managed_line(const char *line, size_t len) {
	if (!line) {
		return false;
	}
	while (len > 0 && (*line == ' ' || *line == '\t')) {
		line++;
		len--;
	}
	return line_has_prefix (line, len, SLEIGH_COMMENT_PREFIX_TAINT)
		|| line_has_prefix (line, len, SLEIGH_COMMENT_PREFIX_TAINT_RISK);
}

static bool is_sla_line_with_prefix(const char *line, size_t len, const char *prefix) {

	if (!line) {
		return false;
	}
	while (len > 0 && (*line == ' ' || *line == '\t')) {
		line++;
		len--;
	}
	return line_has_prefix (line, len, prefix);
}

static bool append_bytes(char **buf, size_t *len, size_t *cap, const char *src, size_t src_len) {
	char *next;

	if (!buf || !len || !cap || !src) {
		return false;
	}
	if (*len + src_len + 1 > *cap) {
		size_t new_cap = *cap ? *cap : 64;
		while (*len + src_len + 1 > new_cap) {
			new_cap *= 2;
		}
		next = realloc (*buf, new_cap);
		if (!next) {
			return false;
		}
		*buf = next;
		*cap = new_cap;
	}
	memcpy (*buf + *len, src, src_len);
	*len += src_len;
	(*buf)[*len] = '\0';
	return true;
}

static char *strip_sla_lines(const char *existing_comment, const char *prefix, bool all_managed) {
	const char *cursor;
	char *out = NULL;
	size_t out_len = 0;
	size_t out_cap = 0;
	bool first = true;

	if (!existing_comment || !*existing_comment) {
		return strdup ("");
	}

	cursor = existing_comment;
	while (*cursor) {
		const char *line_start = cursor;
		const char *line_end = strchr (cursor, '\n');
		size_t line_len = line_end ? (size_t)(line_end - line_start) : strlen (line_start);
		bool should_strip = all_managed
			? is_sla_managed_line (line_start, line_len)
			: is_sla_line_with_prefix (line_start, line_len, prefix);

		if (!should_strip) {
			if (!first) {
				append_bytes (&out, &out_len, &out_cap, "\n", 1);
			}
			append_bytes (&out, &out_len, &out_cap, line_start, line_len);
			first = false;
		}

		if (!line_end) {
			break;
		}
			cursor = line_end + 1;
	}

	if (!out) {
		return strdup ("");
	}
	return out;
}

static char *merge_sla_line(const char *existing_comment, const char *line_to_add, const char *prefix) {
	char *cleaned;
	char *merged;
	size_t cleaned_len;
	size_t line_len;

	if (!line_to_add || !*line_to_add) {
		return strip_sla_lines (existing_comment, prefix, false);
	}

	cleaned = strip_sla_lines (existing_comment, prefix, false);
	if (!cleaned) {
		return NULL;
	}
	if (!*cleaned) {
		free (cleaned);
		return strdup (line_to_add);
	}

	cleaned_len = strlen (cleaned);
	line_len = strlen (line_to_add);
	merged = malloc (cleaned_len + 1 + line_len + 1);
	if (!merged) {
		free (cleaned);
		return NULL;
	}
	memcpy (merged, cleaned, cleaned_len);
	merged[cleaned_len] = '\n';
	memcpy (merged + cleaned_len + 1, line_to_add, line_len);
	merged[cleaned_len + 1 + line_len] = '\0';
	free (cleaned);
	return merged;
}

static void set_sla_comment_line_with_prefix(RAnal *anal, ut64 addr, const char *line, const char *prefix) {
	const char *existing;
	char *updated;

	if (!anal) {
		return;
	}

	existing = r_meta_get_string (anal, R_META_TYPE_COMMENT, addr);
	updated = line
		? merge_sla_line (existing, line, prefix)
		: strip_sla_lines (existing, prefix, false);
	if (!updated) {
		return;
	}

	if (*updated) {
		r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, updated);
	} else {
		r_meta_del (anal, R_META_TYPE_COMMENT, addr, 1);
	}
	free (updated);
}

static void clear_sla_managed_comment_lines(RAnal *anal, ut64 addr) {
	const char *existing;
	char *updated;

	if (!anal) {
		return;
	}
	existing = r_meta_get_string (anal, R_META_TYPE_COMMENT, addr);
	updated = strip_sla_lines (existing, NULL, true);
	if (!updated) {
		return;
	}

	if (*updated) {
		r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, updated);
	} else {
		r_meta_del (anal, R_META_TYPE_COMMENT, addr, 1);
	}
	free (updated);
}

static void set_sla_taint_comment_line(RAnal *anal, ut64 addr, const char *taint_line) {
	set_sla_comment_line_with_prefix (anal, addr, taint_line, SLEIGH_COMMENT_PREFIX_TAINT);
}

static void set_sla_taint_risk_comment_line(RAnal *anal, ut64 addr, const char *risk_line) {
	set_sla_comment_line_with_prefix (anal, addr, risk_line, SLEIGH_COMMENT_PREFIX_TAINT_RISK);
}

static void clear_taint_function_artifacts(RAnal *anal, RCore *core, const RAnalFunction *fcn, const BlockArray *blocks) {
	size_t i;
	char glob[128];
	char risk_glob[128];

	if (!anal || !fcn || !blocks) {
		return;
	}

	if (core && core->flags) {
		snprintf (glob, sizeof (glob), "sla.taint.fcn_%"PFMT64x".*", fcn->addr);
		r_flag_unset_glob (core->flags, glob);
		snprintf (risk_glob, sizeof (risk_glob), "sla.taint.risk.*.fcn_%"PFMT64x, fcn->addr);
		r_flag_unset_glob (core->flags, risk_glob);
	}

	for (i = 0; i < blocks->count; i++) {
		clear_sla_managed_comment_lines (anal, r2il_block_addr (blocks->blocks[i]));
	}
	clear_sla_managed_comment_lines (anal, fcn->addr);
}

static bool has_xref(RAnal *anal, ut64 from, ut64 to, RAnalRefType type) {
	RVecAnalRef *refs;
	size_t i;
	size_t len;

	if (!anal) {
		return false;
	}
	refs = r_anal_xrefs_get (anal, to);
	if (!refs) {
		return false;
	}

	len = RVecAnalRef_length (refs);
	for (i = 0; i < len; i++) {
		RAnalRef *ref = RVecAnalRef_at (refs, i);
		if (ref && ref->at == from && ref->addr == to && ref->type == type) {
			return true;
		}
	}

	return false;
}

static bool maybe_add_taint_xref(RAnal *anal, EdgeSet *seen, ut64 from, ut64 to, RAnalRefType type, int *added_count) {
	if (!anal || !seen || !from || !to) {
		return false;
	}
	if (edge_set_has (seen, from, to)) {
		return false;
	}
	if (!edge_set_add (seen, from, to)) {
		return false;
	}
	if (has_xref (anal, from, to, type)) {
		return false;
	}
	if (r_anal_xrefs_set (anal, from, to, type)) {
		if (added_count) {
			(*added_count)++;
		}
		return true;
	}
	return false;
}

static char *format_taint_summary_comment(TaintBlockSummary *summary) {
	char *comment;
	char *cursor;
	size_t total_len;
	size_t i;
	size_t label_limit;
	int prefix_len;
	int suffix_len;
	char call_count_buf[32];
	const char *call_field = NULL;
	size_t call_field_len = 0;

	if (!summary || !summary->labels || summary->nlabels == 0) {
		return NULL;
	}

	qsort (summary->labels, summary->nlabels, sizeof (char *), cmp_labels_interesting);
	label_limit = R_MIN (summary->nlabels, (size_t)SLEIGH_TAINT_LABEL_MAX);

	if (summary->ncall_names > 0) {
		qsort (summary->call_names, summary->ncall_names, sizeof (char *), cmp_strings_lex);
		call_field_len = 0;
		for (i = 0; i < summary->ncall_names; i++) {
			call_field_len += strlen (summary->call_names[i]);
			if (i > 0) {
				call_field_len += 1;
			}
		}
	} else {
		snprintf (call_count_buf, sizeof (call_count_buf), "%d", summary->call_hits);
		call_field = call_count_buf;
		call_field_len = strlen (call_field);
	}

	prefix_len = snprintf (NULL, 0, "sla.taint: hits=%d calls=", summary->hits);
	suffix_len = snprintf (NULL, 0, " stores=%d labels=", summary->store_hits);
	if (prefix_len < 0 || suffix_len < 0) {
		return NULL;
	}

	total_len = (size_t)prefix_len + call_field_len + (size_t)suffix_len;
	for (i = 0; i < label_limit; i++) {
		total_len += strlen (summary->labels[i]);
		if (i > 0) {
			total_len += 1;
		}
	}
	if (summary->nlabels > label_limit) {
		total_len += 4;
	}

	comment = calloc (1, total_len + 1);
	if (!comment) {
		return NULL;
	}

	snprintf (comment, total_len + 1, "sla.taint: hits=%d calls=", summary->hits);
	cursor = comment + strlen (comment);
	if (summary->ncall_names > 0) {
		for (i = 0; i < summary->ncall_names; i++) {
			if (i > 0) {
				*cursor++ = ',';
			}
			{
				size_t name_len = strlen (summary->call_names[i]);
				memcpy (cursor, summary->call_names[i], name_len);
				cursor += name_len;
			}
		}
	} else {
		size_t count_len = strlen (call_field);
		memcpy (cursor, call_field, count_len);
		cursor += count_len;
	}
	cursor += snprintf (cursor, total_len + 1 - (size_t)(cursor - comment),
		" stores=%d labels=", summary->store_hits);

	for (i = 0; i < label_limit; i++) {
		if (i > 0) {
			*cursor++ = ',';
		}
		size_t label_len = strlen (summary->labels[i]);
		memcpy (cursor, summary->labels[i], label_len);
		cursor += label_len;
	}
	if (summary->nlabels > label_limit) {
		memcpy (cursor, ",...", 4);
		cursor += 4;
	}
	*cursor = '\0';
	return comment;
}

static char *format_taint_risk_comment(
	TaintRiskLevel level,
	char **call_names,
	size_t ncall_names,
	int call_hits,
	int store_hits,
	char **labels,
	size_t nlabels
) {
	char *comment;
	char *cursor;
	size_t total_len = 0;
	size_t i;
	size_t label_limit;
	const char *level_name;
	char call_count_buf[32];
	const char *call_field = NULL;
	size_t call_field_len = 0;

	if (level == TAINT_RISK_NONE) {
		return NULL;
	}

	level_name = taint_risk_level_name (level);
	if (!level_name || !*level_name) {
		return NULL;
	}

	if (ncall_names > 0) {
		qsort (call_names, ncall_names, sizeof (char *), cmp_strings_lex);
		for (i = 0; i < ncall_names; i++) {
			call_field_len += strlen (call_names[i]);
			if (i > 0) {
				call_field_len += 1;
			}
		}
	} else {
		snprintf (call_count_buf, sizeof (call_count_buf), "%d", call_hits);
		call_field = call_count_buf;
		call_field_len = strlen (call_field);
	}

	if (!labels || nlabels == 0) {
		return NULL;
	}
	qsort (labels, nlabels, sizeof (char *), cmp_labels_interesting);
	label_limit = R_MIN (nlabels, (size_t)SLEIGH_TAINT_LABEL_MAX);

	total_len += (size_t)snprintf (NULL, 0, "sla.taint.risk: %s (calls=", level_name);
	total_len += call_field_len;
	total_len += (size_t)snprintf (NULL, 0, " stores=%d labels=", store_hits);
	for (i = 0; i < label_limit; i++) {
		total_len += strlen (labels[i]);
		if (i > 0) {
			total_len += 1;
		}
	}
	if (nlabels > label_limit) {
		total_len += 4;
	}
	total_len += 1; /* ')' */

	comment = calloc (1, total_len + 1);
	if (!comment) {
		return NULL;
	}

	snprintf (comment, total_len + 1, "sla.taint.risk: %s (calls=", level_name);
	cursor = comment + strlen (comment);
	if (ncall_names > 0) {
		for (i = 0; i < ncall_names; i++) {
			if (i > 0) {
				*cursor++ = ',';
			}
			{
				size_t name_len = strlen (call_names[i]);
				memcpy (cursor, call_names[i], name_len);
				cursor += name_len;
			}
		}
	} else {
		size_t count_len = strlen (call_field);
		memcpy (cursor, call_field, count_len);
		cursor += count_len;
	}

	cursor += snprintf (cursor, total_len + 1 - (size_t)(cursor - comment),
		" stores=%d labels=", store_hits);
	for (i = 0; i < label_limit; i++) {
		if (i > 0) {
			*cursor++ = ',';
		}
		{
			size_t label_len = strlen (labels[i]);
			memcpy (cursor, labels[i], label_len);
			cursor += label_len;
		}
	}
	if (nlabels > label_limit) {
		memcpy (cursor, ",...", 4);
		cursor += 4;
	}
	*cursor++ = ')';
	*cursor = '\0';
	return comment;
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
			/* Check if this block has switch info from radare2's analysis */
			if (bb->switch_op && bb->switch_op->cases) {
				size_t num_cases = r_list_length (bb->switch_op->cases);
				if (num_cases > 0) {
					unsigned long long *case_values = malloc (num_cases * sizeof (unsigned long long));
					unsigned long long *case_targets = malloc (num_cases * sizeof (unsigned long long));
					if (case_values && case_targets) {
						RListIter *case_iter;
						RAnalCaseOp *case_op;
						size_t i = 0;
						r_list_foreach (bb->switch_op->cases, case_iter, case_op) {
							case_values[i] = case_op->value;
							case_targets[i] = case_op->jump;
							i++;
						}
						r2il_block_set_switch_info (block,
							bb->switch_op->addr,
							bb->switch_op->min_val,
							bb->switch_op->max_val,
							bb->switch_op->def_val,
							case_values, case_targets, num_cases);
					}
					free (case_values);
					free (case_targets);
				}
			}
			block_array_push (out, block);
		}
	}

	return out->count > 0;
}

R2ILContext *get_context(RAnal *anal) {
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
	sleigh_ctx = r2il_arch_init (sleigh_arch_str);
	if (!sleigh_ctx) {
		R_LOG_ERROR ("r2sleigh: failed to initialize context for %s", sleigh_arch_str);
		return NULL;
	}

	if (!r2il_is_loaded (sleigh_ctx)) {
		const char *err = r2il_error (sleigh_ctx);
		if (err) {
			R_LOG_ERROR ("r2sleigh: %s", err);
		}
		r2il_free (sleigh_ctx);
		sleigh_ctx = NULL;
		return NULL;
	}

	sleigh_arch = strdup (sleigh_arch_str);

	/* Set register profile from Sleigh definitions */
	char *profile = r2il_get_reg_profile (sleigh_ctx);
	if (profile) {
		r_anal_set_reg_profile (anal, profile);
		r2il_string_free (profile);
	}

	return sleigh_ctx;
}

int sleigh_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	ensure_sleigh_pdd_core_plugin (anal);
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

	if (mask & R_ARCH_OP_MASK_VAL) {
		// Clear existing values first
		RVecRArchValue_clear (&op->srcs);
		RVecRArchValue_clear (&op->dsts);

		// Use enhanced value filling with memory/immediate support
		fill_op_values_enhanced (anal, op, ctx, block);

		// Add stack operation metadata
		analyze_stack_operation (ctx, block, op);

		// Set operation direction
		set_operation_direction (ctx, block, op);
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
	cleanup_sleigh_pdd_core_plugin ();
	if (sleigh_ctx) {
		r2il_free (sleigh_ctx);
		sleigh_ctx = NULL;
	}
	free (sleigh_arch);
	sleigh_arch = NULL;
	sym_state_cache_clear ();
	return true;
}

static char *sleigh_cmd(RAnal *anal, const char *cmd) {
	ensure_sleigh_pdd_core_plugin (anal);
	bool is_sla_ns = r_str_startswith (cmd, "sla");
	bool is_sym_ns = r_str_startswith (cmd, "sym");
	if (!is_sla_ns && !is_sym_ns) {
		return NULL;
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
			r_cons_println (cons, "| a:sla.opvals - Show analysis srcs/dsts for current instruction");
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
			r_cons_println (cons, "| a:sla.dec [name|addr] - Decompile function (current by default)");
			r_cons_println (cons, "| pdd/pdD [name|addr] - Alias for a:sla.dec [name|addr]");
			r_cons_println (cons, "| a:sla.cfg    - Show ASCII CFG for current function");
			r_cons_println (cons, "| a:sla.cfg.json - Show CFG as JSON for current function");
			r_cons_println (cons, "| a:sym.explore <target> - Explore symbolic paths reaching target");
			r_cons_println (cons, "| a:sym.solve <target> - Solve concrete input for target reachability");
			r_cons_println (cons, "| a:sym.state  - Show last symbolic explore/solve cached result");
		}
		return strdup("");
	}

	if (is_sym_ns && !strcmp (cmd, "sym.state")) {
		char *state_json = sym_state_cache_to_json ();
		if (cons && state_json) {
			r_cons_printf (cons, "%s\n", state_json);
		}
		free (state_json);
		return strdup("");
	}

	if (is_sym_ns && (!strncmp (cmd, "sym.explore", 11) || !strncmp (cmd, "sym.solve", 9))) {
		bool is_explore = r_str_startswith (cmd, "sym.explore");
		size_t prefix_len = is_explore ? 11 : 9;
		const char *arg = skip_cmd_spaces (cmd + prefix_len);
		ut64 target = 0;
		R2ILContext *ctx;
		RAnalFunction *fcn;
		BlockArray blocks;
		char *result = NULL;
		bool rust_owned = true;

		if (!arg || !*arg) {
			if (cons) {
				r_cons_println (cons, is_explore
					? "Usage: a:sym.explore <target_addr_expr>"
					: "Usage: a:sym.solve <target_addr_expr>");
			}
			return strdup("");
		}
		if (!parse_sym_target_expr (core, arg, &target)) {
			R_LOG_ERROR ("r2sleigh: invalid symbolic target expression: %s", arg);
			if (cons) {
				r_cons_println (cons, is_explore
					? "Usage: a:sym.explore <target_addr_expr>"
					: "Usage: a:sym.solve <target_addr_expr>");
			}
			return strdup("");
		}

		ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}
		fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}
		char *sym_map_json = build_sym_symbol_map_json (core);
		if (sym_map_json) {
			r2sym_set_symbol_map_json (sym_map_json);
			free (sym_map_json);
		}

		if (is_explore) {
			result = r2sym_explore_to (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr, target);
		} else {
			result = r2sym_solve_to (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr, target);
		}
		if (!result) {
			rust_owned = false;
			result = strdup ("{\"error\":\"symbolic execution failed\"}");
		}

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}
		if (result && !sym_result_has_error (result)) {
			sym_state_cache_update (is_explore ? "explore" : "solve", fcn->addr, fcn->addr, target, result);
		}

		if (rust_owned) {
			r2il_string_free (result);
		} else {
			free (result);
		}
		block_array_free (&blocks);
		return strdup("");
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
		return strdup("");
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
		return strdup("");
	}

	if (!strcmp (cmd, "sla.json")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current seek */
		ut64 addr = core->addr;

		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
		}

		size_t count = r2il_block_op_count (block);
		if (cons) {
			r_cons_println (cons, "[");
		}
		if (count == 0) {
			if (cons) {
				r_cons_println (cons, "  {\"Nop\":{},\"note\":\"instruction lifted with no semantic ops\"}");
			}
		} else {
			size_t i;
			for (i = 0; i < count; i++) {
				char *json = r2il_block_op_json_named (ctx, block, i);
				if (json && cons) {
					r_cons_printf (cons, "  %s%s\n", json, (i + 1 < count) ? "," : "");
					r2il_string_free (json);
				}
			}
		}
		if (cons) {
			r_cons_println (cons, "]");
		}

		r2il_block_free (block);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.regs")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
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
		return strdup("");
	}

	if (!strcmp (cmd, "sla.opvals")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
		}

		RVecRArchValue srcs;
		RVecRArchValue dsts;
		RVecRArchValue_init (&srcs);
		RVecRArchValue_init (&dsts);

		char *defuse_json = r2il_block_defuse_json (ctx, block);
		if (defuse_json) {
			RJson *root = r_json_parse (defuse_json);
			if (root && root->type == R_JSON_OBJECT) {
				const RJson *inputs = r_json_get (root, "inputs");
				const RJson *outputs = r_json_get (root, "outputs");
				add_ssa_reg_values (anal, inputs, &srcs, R_PERM_R);
				add_ssa_reg_values (anal, outputs, &dsts, R_PERM_W);
			}
			r_json_free (root);
			r2il_string_free (defuse_json);
		}

		if (cons) {
			r_cons_print (cons, "{\"srcs\":[");
			print_reg_values_json (cons, &srcs);
			r_cons_print (cons, "],\"dsts\":[");
			print_reg_values_json (cons, &dsts);
			r_cons_println (cons, "]}");
		}

		RVecRArchValue_fini (&srcs);
		RVecRArchValue_fini (&dsts);
		r2il_block_free (block);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.mem")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
		}

		char *mem_json = r2il_block_mem_access (ctx, block);
		if (cons && mem_json) {
			r_cons_printf (cons, "%s\n", mem_json);
		}

		r2il_string_free (mem_json);
		r2il_block_free (block);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.vars")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
		}

		char *vars_json = r2il_block_varnodes (ctx, block);
		if (cons && vars_json) {
			r_cons_printf (cons, "%s\n", vars_json);
		}

		r2il_string_free (vars_json);
		r2il_block_free (block);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.ssa")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
		}

		char *ssa_json = r2il_block_to_ssa_json (ctx, block);
		if (cons && ssa_json) {
			r_cons_printf (cons, "%s\n", ssa_json);
		}

		r2il_string_free (ssa_json);
		r2il_block_free (block);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.defuse")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		ut64 addr = core->addr;
		ut8 buf[SLEIGH_MIN_BYTES];
		if (!anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf))) {
			R_LOG_ERROR ("r2sleigh: failed to read bytes at 0x%"PFMT64x, addr);
			return strdup("");
		}

		R2ILBlock *block = r2il_lift (ctx, buf, sizeof (buf), addr);
		if (!block) {
			R_LOG_ERROR ("r2sleigh: lift failed");
			return strdup("");
		}

		char *defuse_json = r2il_block_defuse_json (ctx, block);
		if (cons && defuse_json) {
			r_cons_printf (cons, "%s\n", defuse_json);
		}

		r2il_string_free (defuse_json);
		r2il_block_free (block);
		return strdup("");
	}

	/* ========== Function-level SSA commands ========== */

	if (!strcmp (cmd, "sla.ssa.func")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		/* Get function SSA */
		char *result = r2ssa_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.ssa.func.opt")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		char *result = r2ssa_function_opt_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.defuse.func")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		/* Get function def-use analysis */
		char *result = r2ssa_defuse_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return strdup("");
	}

	if (!strcmp (cmd, "sla.dom")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		/* Get dominator tree */
		char *result = r2ssa_domtree_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return strdup("");
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
			return strdup("");
		}

		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		/* Get backward slice */
		char *result = r2ssa_backward_slice_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count, arg);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return strdup("");
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
				return strdup("");
			}
		} else {
			int enabled = r2sym_merge_is_enabled ();
			r2sym_merge_set_enabled (!enabled);
		}

		if (cons) {
			r_cons_printf (cons, "sym merge: %s\n", r2sym_merge_is_enabled () ? "on" : "off");
		}
		return strdup("");
	}

	if (!strcmp (cmd, "sla.sym") || !strcmp (cmd, "sla.sym.paths")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}
		char *sym_map_json = build_sym_symbol_map_json (core);
		if (sym_map_json) {
			r2sym_set_symbol_map_json (sym_map_json);
			free (sym_map_json);
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
		return strdup("");
	}

	if (!strcmp (cmd, "sla.taint")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		char *result = r2taint_function_json (ctx, (const R2ILBlock **)blocks.blocks, blocks.count);

		if (cons && result) {
			r_cons_printf (cons, "%s\n", result);
		}

		r2il_string_free (result);
		block_array_free (&blocks);
		return strdup("");
	}

	if (!strncmp (cmd, "sla.dec", 7)) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		const char *target_arg = skip_cmd_spaces (cmd + 7);
		RAnalFunction *fcn = NULL;
		if (target_arg && *target_arg) {
			ut64 target_addr = 0;
			if (parse_sym_target_expr (core, target_arg, &target_addr)) {
				fcn = r_anal_get_fcn_in (anal, target_addr, R_ANAL_FCN_TYPE_ANY);
			} else {
				fcn = r_anal_get_function_byname (anal, target_arg);
			}
		} else {
			fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		}

		if (!fcn) {
			if (target_arg && *target_arg) {
				if (cons) {
					r_cons_printf (cons,
						"/* r2dec: function target '%s' not found. It may be inlined or stripped. Try 'afl' or 'a:sla.dec 0xADDR'. */\n",
						target_arg);
				}
			} else {
				R_LOG_ERROR ("r2sleigh: no function at current address");
			}
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
		}

		/* Gather function names from r2 */
		char *func_names_json = NULL;
		char *strings_json = NULL;
		char *symbols_json = NULL;
		char *signature_json = NULL;
		char *stack_vars_json = NULL;
		char *types_json = NULL;

		/* Get function list as JSON and convert to our format */
		/* aflj returns [{addr:0x401000,name:"main"}, ...] */
		char *aflj = r_core_cmd_str (core, "aflj");
		if (aflj && aflj[0] == '[') {
			/* Convert to {addr: name} format */
			PJ *pj = pj_new ();
			pj_o (pj);
			/* Parse the array manually */
			RJson *root = r_json_parse (aflj);
			if (root && root->type == R_JSON_ARRAY) {
				RJson *elem;
				for (elem = root->children.first; elem; elem = elem->next) {
					if (elem->type == R_JSON_OBJECT) {
						const RJson *addr = r_json_get (elem, "addr");
						const RJson *name = r_json_get (elem, "name");
						if (addr && name && addr->type == R_JSON_INTEGER && name->type == R_JSON_STRING) {
							char addr_str[32];
							snprintf (addr_str, sizeof(addr_str), "0x%llx", (unsigned long long)addr->num.u_value);
							pj_ks (pj, addr_str, name->str_value);
						}
					}
				}
				r_json_free (root);
			}
			pj_end (pj);
			func_names_json = pj_drain (pj);
		}
		free (aflj);

		/* Get strings: izj returns [{vaddr:0x402000,string:"Hello"}, ...] */
		char *izj = r_core_cmd_str (core, "izj");
		if (izj && izj[0] == '[') {
			PJ *pj = pj_new ();
			pj_o (pj);
			RJson *root = r_json_parse (izj);
			if (root && root->type == R_JSON_ARRAY) {
				RJson *elem;
				for (elem = root->children.first; elem; elem = elem->next) {
					if (elem->type == R_JSON_OBJECT) {
						const RJson *vaddr = r_json_get (elem, "vaddr");
						const RJson *str = r_json_get (elem, "string");
						if (vaddr && str && vaddr->type == R_JSON_INTEGER && str->type == R_JSON_STRING) {
							char addr_str[32];
							snprintf (addr_str, sizeof(addr_str), "0x%llx", (unsigned long long)vaddr->num.u_value);
							pj_ks (pj, addr_str, str->str_value);
						}
					}
				}
				r_json_free (root);
			}
			pj_end (pj);
			strings_json = pj_drain (pj);
		}
		free (izj);

		/* Get global symbols/flags: fj returns [{name:"sym.foo",offset:0x401000}, ...] */
		/* Use 'fs *;fj' to get flags from all flagspaces (including relocs) */
		char *fj = r_core_cmd_str (core, "fs *;fj");
		if (fj && fj[0] == '[') {
			PJ *pj = pj_new ();
			pj_o (pj);
			RJson *root = r_json_parse (fj);
			if (root && root->type == R_JSON_ARRAY) {
				RJson *elem;
				for (elem = root->children.first; elem; elem = elem->next) {
					if (elem->type == R_JSON_OBJECT) {
						const RJson *offset = r_json_get (elem, "addr");
						const RJson *name = r_json_get (elem, "name");
						if (offset && name && offset->type == R_JSON_INTEGER && name->type == R_JSON_STRING) {
							/* Skip strings (already in strings_json), sections, and low-signal linker/locator symbols */
							const char *n = name->str_value;
							if (n && strncmp (n, "str.", 4) != 0
							    && strncmp (n, "section.", 8) != 0
							    && strncmp (n, "loc.", 4) != 0
							    && strcmp (n, "obj.__TMC_END__") != 0
							    && strcmp (n, "obj.__FRAME_END__") != 0
							    && strcmp (n, "obj.__dso_handle") != 0
							    && strcmp (n, "obj.completed.0") != 0) {
								char addr_str[32];
								snprintf (addr_str, sizeof (addr_str), "0x%llx", (unsigned long long)offset->num.u_value);
								pj_ks (pj, addr_str, n);
							}
						}
					}
				}
				r_json_free (root);
			}
			pj_end (pj);
			symbols_json = pj_drain (pj);
		}
		free (fj);

		/* Build signature context payload:
		 * {"current":[...], "known":[...], "cc":{...}}
		 * Keep single FFI argument for ABI stability.
		 */
		char *signature_current_json = r_core_cmd_str (core, "afcfj");
		if (!signature_current_json || signature_current_json[0] != '[') {
			free (signature_current_json);
			signature_current_json = strdup ("[]");
		}

		char *signature_known_json = r_core_cmd_str (core, "aflj");
		if (!signature_known_json || signature_known_json[0] != '[') {
			free (signature_known_json);
			signature_known_json = strdup ("[]");
		}

		char *cc_json = r_core_cmd_str (core, "tccj");
		if (!cc_json || (cc_json[0] != '{' && cc_json[0] != '[')) {
			free (cc_json);
			cc_json = strdup ("{}");
		}

		signature_json = r_str_newf (
			"{\"current\":%s,\"known\":%s,\"cc\":%s}",
			signature_current_json,
			signature_known_json,
			cc_json
		);
		free (signature_current_json);
		free (signature_known_json);
		free (cc_json);
		if (!signature_json) {
			signature_json = strdup ("{\"current\":[],\"known\":[],\"cc\":{}}");
		}

			/* Get recovered function variables metadata for current function. */
			stack_vars_json = r_core_cmd_str (core, "afvj");
			if (!stack_vars_json || stack_vars_json[0] != '{') {
				free (stack_vars_json);
				stack_vars_json = strdup ("{}");
			}

			/* Get host type DB metadata (structs) in JSON form. */
			types_json = r_core_cmd_str (core, "tsj");
			if (!types_json || (types_json[0] != '{' && types_json[0] != '[')) {
				free (types_json);
				types_json = strdup ("{}");
			}

			/* Decompile with context */
			char *result = r2dec_function_with_context (ctx, (const R2ILBlock **)blocks.blocks, blocks.count,
			                                             fcn->name, func_names_json, strings_json, symbols_json,
			                                             signature_json, stack_vars_json, types_json);

		if (cons) {
			if (result && result[0]) {
				r_cons_printf (cons, "%s\n", result);
			} else {
				const char *fname = (fcn && fcn->name) ? fcn->name : "unknown";
				r_cons_printf (cons, "/* r2dec fallback: empty decompilation output for %s */\n", fname);
			}
		}

		if (result) {
			r2il_string_free (result);
		}
		free (func_names_json);
		free (strings_json);
			free (symbols_json);
			free (signature_json);
			free (stack_vars_json);
			free (types_json);
			block_array_free (&blocks);
			return strdup("");
		}

	if (!strcmp (cmd, "sla.cfg") || !strcmp (cmd, "sla.cfg.json")) {
		R2ILContext *ctx = get_context (anal);
		if (!ctx) {
			R_LOG_ERROR ("r2sleigh: no context");
			return strdup("");
		}

		/* Get current function */
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, core->addr, R_ANAL_FCN_TYPE_ANY);
		if (!fcn) {
			R_LOG_ERROR ("r2sleigh: no function at current address");
			return strdup("");
		}

		/* Lift all blocks */
		BlockArray blocks;
		if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
			R_LOG_ERROR ("r2sleigh: failed to lift function blocks");
			return strdup("");
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
		return strdup("");
	}

	R_LOG_ERROR ("Unknown subcommand. See 'a:sla?' or 'a:sym?' for help");
	return strdup("");
}

/* ============================================================================
 * radare2 Deep Integration Callbacks
 * These are called automatically by radare2 during analysis (aaa, afv, ax)
 * ============================================================================ */

/* Called after function analysis completes */
static bool sleigh_analyze_fcn(RAnal *anal, RAnalFunction *fcn) {
	ensure_sleigh_pdd_core_plugin (anal);
	if (!fcn || !anal) {
		return false;
	}

	R2ILContext *ctx = get_context (anal);
	if (!ctx) {
		return false;
	}

	BlockArray blocks;
	if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
		return false;
	}

	int result = r2sleigh_analyze_fcn (ctx,
		(const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);

	/* Write SSA annotations as comments */
	char *json = r2sleigh_analyze_fcn_annotations (ctx,
		(const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);
	if (json && *json) {
		RJson *root = r_json_parse (json);
		if (root && root->type == R_JSON_ARRAY) {
			const RJson *item;
			for (item = root->children.first; item; item = item->next) {
				if (item->type != R_JSON_OBJECT) {
					continue;
				}
				const RJson *j_addr = r_json_get (item, "addr");
				const RJson *j_comment = r_json_get (item, "comment");
				if (j_addr && j_comment && j_comment->str_value) {
					r_meta_set_string (anal, R_META_TYPE_COMMENT,
						(ut64)j_addr->num.u_value, j_comment->str_value);
				}
			}
			r_json_free (root);
		}
		r2il_string_free (json);
	}

	block_array_free (&blocks);
	return result == 1;
}

/* Helper to free RAnalVarProt */
static void var_prot_free(void *ptr) {
	if (!ptr) {
		return;
	}
	RAnalVarProt *prot = (RAnalVarProt *)ptr;
	free (prot->name);
	free (prot->type);
	free (prot);
}

/* Called during variable recovery (afva) */
static RList *sleigh_recover_vars(RAnal *anal, RAnalFunction *fcn) {
	ensure_sleigh_pdd_core_plugin (anal);
	if (!fcn || !anal) {
		return NULL;
	}

	R2ILContext *ctx = get_context (anal);
	if (!ctx) {
		return NULL;
	}

	BlockArray blocks;
	if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
		return NULL;
	}

	char *json = r2sleigh_recover_vars (ctx,
		(const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);

	block_array_free (&blocks);

	if (!json || !*json) {
		r2il_string_free (json);
		return NULL;
	}

	/* Parse JSON and create RList of RAnalVarProt */
	RList *vars = r_list_newf ((RListFree)var_prot_free);
	if (!vars) {
		r2il_string_free (json);
		return NULL;
	}

	RJson *root = r_json_parse (json);
	if (!root || root->type != R_JSON_ARRAY) {
		r2il_string_free (json);
		r_list_free (vars);
		return NULL;
	}

	const RJson *item;
	for (item = root->children.first; item; item = item->next) {
		if (item->type != R_JSON_OBJECT) {
			continue;
		}

		const RJson *j_name = r_json_get (item, "name");
		const RJson *j_kind = r_json_get (item, "kind");
		const RJson *j_delta = r_json_get (item, "delta");
		const RJson *j_type = r_json_get (item, "type");
		const RJson *j_isarg = r_json_get (item, "isarg");
		const RJson *j_reg = r_json_get (item, "reg");

		if (!j_name || !j_kind || !j_delta || !j_type) {
			continue;
		}

		RAnalVarProt *prot = R_NEW0 (RAnalVarProt);
		if (!prot) {
			continue;
		}

		prot->name = strdup (j_name->str_value ? j_name->str_value : "");
		prot->type = strdup (j_type->str_value ? j_type->str_value : "int64_t");
		prot->delta = (st64)j_delta->num.s_value;
		prot->isarg = j_isarg && j_isarg->type == R_JSON_BOOLEAN && j_isarg->num.u_value;

		/* Parse kind: "r" = register, "s" = stack, "b" = bp-relative */
		if (j_kind->str_value) {
			switch (j_kind->str_value[0]) {
			case 'r':
				/* Register-based argument: use r_reg_get to find index */
				if (j_reg && j_reg->str_value && anal->reg) {
					/* Try uppercase version (Sleigh uses uppercase reg names) */
					char *upper_reg = strdup (j_reg->str_value);
					if (upper_reg) {
						for (char *p = upper_reg; *p; p++) {
							*p = toupper ((unsigned char)*p);
						}
					}
					RRegItem *ri = upper_reg
						? r_reg_get (anal->reg, upper_reg, R_REG_TYPE_GPR)
						: NULL;
					if (!ri) {
						/* Try original case as fallback */
						ri = r_reg_get (anal->reg, j_reg->str_value, R_REG_TYPE_GPR);
					}
					free (upper_reg);
					if (ri) {
						prot->kind = R_ANAL_VAR_KIND_REG;
						prot->delta = ri->index;
					} else {
						/* Reg lookup failed, skip this arg */
						free (prot->name);
						free (prot->type);
						free (prot);
						continue;
					}
				} else {
					/* No reg name provided, skip */
					free (prot->name);
					free (prot->type);
					free (prot);
					continue;
				}
				break;
			case 's':
				prot->kind = R_ANAL_VAR_KIND_SPV;
				break;
			case 'b':
				prot->kind = R_ANAL_VAR_KIND_BPV;
				break;
			default:
				prot->kind = R_ANAL_VAR_KIND_SPV;
			}
		}

		r_list_append (vars, prot);
	}

	r_json_free (root);
	r2il_string_free (json);

	if (r_list_empty (vars)) {
		r_list_free (vars);
		return NULL;
	}

	return vars;
}

/* Called during reference analysis (aar) */
static RVecAnalRef *sleigh_get_data_refs(RAnal *anal, RAnalFunction *fcn) {
	ensure_sleigh_pdd_core_plugin (anal);
	if (!fcn || !anal) {
		return NULL;
	}

	R2ILContext *ctx = get_context (anal);
	if (!ctx) {
		return NULL;
	}

	BlockArray blocks;
	if (!lift_function_blocks (anal, fcn, ctx, &blocks)) {
		return NULL;
	}

	char *json = r2sleigh_get_data_refs (ctx,
		(const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);

	block_array_free (&blocks);

	if (!json || !*json) {
		r2il_string_free (json);
		return NULL;
	}

	/* Parse JSON and create RVecAnalRef */
	RVecAnalRef *refs = RVecAnalRef_new ();
	if (!refs) {
		r2il_string_free (json);
		return NULL;
	}

	RJson *root = r_json_parse (json);
	if (!root || root->type != R_JSON_ARRAY) {
		r2il_string_free (json);
		RVecAnalRef_free (refs);
		return NULL;
	}

	const RJson *item;
	for (item = root->children.first; item; item = item->next) {
		if (item->type != R_JSON_OBJECT) {
			continue;
		}

		const RJson *j_from = r_json_get (item, "from");
		const RJson *j_to = r_json_get (item, "to");
		const RJson *j_type = r_json_get (item, "type");

		if (!j_from || !j_to) {
			continue;
		}

		ut64 from_addr = (ut64)j_from->num.u_value;
		ut64 to_addr = (ut64)j_to->num.u_value;

		/* Skip intra-function refs: if the target is within the same
		 * function, r2 already has these as code xrefs from the CFG. */
		if (to_addr >= fcn->addr && to_addr < fcn->addr + r_anal_function_linear_size (fcn)) {
			continue;
		}

		RAnalRef ref = {
			.at = from_addr,
			.addr = to_addr,
			.type = R_ANAL_REF_TYPE_DATA  /* default to data ref */
		};

		/* Parse type if present */
		if (j_type && j_type->str_value) {
			switch (j_type->str_value[0]) {
			case 'c':
			case 'C':
				ref.type = R_ANAL_REF_TYPE_CALL;
				break;
			case 'j':
			case 'J':
				ref.type = R_ANAL_REF_TYPE_JUMP;
				break;
			case 's':
			case 'S':
				ref.type = R_ANAL_REF_TYPE_STRN;
				break;
			default:
				/* If the target is inside a known function, emit as
				 * CODE ref (function pointer) rather than DATA. */
				if (r_anal_get_fcn_in (anal, to_addr, 0)) {
					ref.type = R_ANAL_REF_TYPE_CODE;
				} else {
					ref.type = R_ANAL_REF_TYPE_DATA;
				}
			}
		}

		RVecAnalRef_push_back (refs, &ref);
	}

	r_json_free (root);
	r2il_string_free (json);

	if (RVecAnalRef_empty (refs)) {
		RVecAnalRef_free (refs);
		return NULL;
	}

	return refs;
}

static bool core_cmd_succeeds (RCore *core, const char *cmd) {
	if (!core || !cmd || !*cmd) {
		return false;
	}
	char *out = r_core_cmd_str (core, cmd);
	bool ok = out && !strstr (out, "ERROR:");
	free (out);
	return ok;
}

static bool is_signature_writeback_arch_supported (const char *arch_name) {
	return arch_name
		&& (!strcmp (arch_name, "x86") || !strcmp (arch_name, "x86-64")
		|| !strcmp (arch_name, "x86_64") || !strcmp (arch_name, "x64")
		|| !strcmp (arch_name, "amd64"));
}

static const RJson *json_next_object (const RJson *item) {
	const RJson *cur = item;
	while (cur && cur->type != R_JSON_OBJECT) {
		cur = cur->next;
	}
	return cur;
}

static char *normalize_compare_string (const char *s) {
	size_t len;
	char *out;
	size_t i;
	size_t j = 0;

	if (!s) {
		return strdup ("");
	}
	len = strlen (s);
	out = malloc (len + 1);
	if (!out) {
		return strdup ("");
	}
	for (i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)s[i];
		if (isspace (ch) || ch == ';') {
			continue;
		}
		out[j++] = (char)tolower (ch);
	}
	out[j] = '\0';
	return out;
}

static bool strings_match_normalized (const char *a, const char *b) {
	char *na = normalize_compare_string (a);
	char *nb = normalize_compare_string (b);
	bool match;
	if (!na || !nb) {
		free (na);
		free (nb);
		return false;
	}
	match = !strcmp (na, nb);
	free (na);
	free (nb);
	return match;
}

static bool apply_inferred_signature (RAnal *anal, RCore *core, RAnalFunction *fcn, const char *signature) {
	int rc;
	char *sig_cmd;

	if (!anal || !fcn || !signature || !*signature) {
		return false;
	}
	rc = r_anal_str_to_fcn (anal, fcn, signature);
	if (rc > 0) {
		return true;
	}
	if (!core) {
		return false;
	}
	sig_cmd = r_str_newf ("afs %s @ 0x%"PFMT64x, signature, fcn->addr);
	if (!sig_cmd) {
		return false;
	}
	if (core_cmd_succeeds (core, sig_cmd)) {
		free (sig_cmd);
		return true;
	}
	free (sig_cmd);
	return false;
}

static bool apply_inferred_callconv (RAnal *anal, RCore *core, RAnalFunction *fcn, const char *cc_name) {
	const char *pooled_cc = NULL;
	char *cc_cmd;

	if (!anal || !fcn || !cc_name || !*cc_name) {
		return false;
	}
	if (r_anal_cc_exist (anal, cc_name)) {
		pooled_cc = r_str_constpool_get (&anal->constpool, cc_name);
		if (pooled_cc) {
			fcn->callconv = pooled_cc;
			return true;
		}
	}
	if (!core) {
		return false;
	}
	cc_cmd = r_str_newf ("afc %s @ 0x%"PFMT64x, cc_name, fcn->addr);
	if (!cc_cmd) {
		return false;
	}
	if (core_cmd_succeeds (core, cc_cmd)) {
		free (cc_cmd);
		return true;
	}
	free (cc_cmd);
	return false;
}

static bool is_caller_propagation_ref_type (RAnalRefType type) {
	RAnalRefType masked = R_ANAL_REF_TYPE_MASK (type);
	return masked == R_ANAL_REF_TYPE_CALL
		|| masked == R_ANAL_REF_TYPE_CODE
		|| masked == R_ANAL_REF_TYPE_JUMP;
}

static bool run_caller_type_match (RAnal *anal, RAnalFunction *caller_fcn) {
	if (!anal || !caller_fcn) {
		return false;
	}
	r_anal_type_match (anal, caller_fcn);
	return true;
}

static bool run_caller_afva (RCore *core, RAnalFunction *caller_fcn) {
	if (!core || !caller_fcn) {
		return false;
	}
	r_core_recover_vars (core, caller_fcn, false);
	return true;
}

static void caller_propagation_record_sample(
	CallerPropagationState *state,
	const char *callee_name,
	bool prioritize
) {
	size_t i;
	size_t last;
	char *dup;

	if (!state || !callee_name || !*callee_name) {
		return;
	}
	for (i = 0; i < state->sample_callees_count; i++) {
		if (!strcmp (state->sample_callees[i], callee_name)) {
			return;
		}
	}
	if (state->sample_callees_count < SLEIGH_CALLER_PROP_SAMPLE_MAX) {
		append_unique_string (&state->sample_callees, &state->sample_callees_count,
			&state->sample_callees_capacity, callee_name);
		return;
	}
	if (!prioritize || state->sample_callees_count == 0) {
		return;
	}
	dup = strdup (callee_name);
	if (!dup) {
		return;
	}
	last = state->sample_callees_count - 1;
	free (state->sample_callees[last]);
	state->sample_callees[last] = dup;
}

static void propagate_signature_to_direct_callers(
	RAnal *anal,
	RCore *core,
	ut64 callee_addr,
	const char *callee_name,
	CallerPropagationState *state,
	bool prioritize_sample
) {
	RVecAnalRef *refs;
	ut64 *callee_callers = NULL;
	size_t callee_callers_count = 0;
	size_t callee_callers_capacity = 0;
	size_t i;
	size_t len;
	int callee_updates = 0;

	if (!anal || !core || !state || !callee_addr) {
		return;
	}
	if (state->prop_callees_triggered >= SLEIGH_CALLER_PROP_MAX_CALLEES) {
		state->prop_callees_skipped_cap++;
		return;
	}
	refs = r_anal_xrefs_get (anal, callee_addr);
	if (!refs) {
		return;
	}

	state->prop_callees_triggered++;
	caller_propagation_record_sample (state, callee_name, prioritize_sample);

	len = RVecAnalRef_length (refs);
	for (i = 0; i < len; i++) {
		RAnalRef *ref = RVecAnalRef_at (refs, i);
		if (!ref || !ref->at || !is_caller_propagation_ref_type (ref->type)) {
			continue;
		}
		append_unique_ut64 (&callee_callers, &callee_callers_count, &callee_callers_capacity, ref->at);
	}

	for (i = 0; i < callee_callers_count; i++) {
		ut64 caller_site = callee_callers[i];
		RAnalFunction *caller_fcn;
		ut64 caller_addr;

		state->prop_callers_considered++;
		caller_fcn = r_anal_get_fcn_in (anal, caller_site, 0);
		if (!caller_fcn) {
			state->prop_callers_missing_fcn++;
			continue;
		}
		caller_addr = caller_fcn->addr;
		if (ut64_array_contains (state->updated_callers, state->updated_callers_count, caller_addr)) {
			state->prop_callers_dedup_skipped++;
			continue;
		}
		if (callee_updates >= SLEIGH_CALLER_PROP_MAX_CALLERS_PER_CALLEE) {
			state->prop_callers_per_callee_cap_skipped++;
			continue;
		}
		if (state->prop_callers_updated >= SLEIGH_CALLER_PROP_MAX_CALLERS_TOTAL) {
			state->prop_callers_total_cap_skipped++;
			continue;
		}
		if (!append_unique_ut64 (&state->updated_callers, &state->updated_callers_count,
				&state->updated_callers_capacity, caller_addr)) {
			state->prop_callers_total_cap_skipped++;
			continue;
		}
		if (!run_caller_type_match (anal, caller_fcn)) {
			state->prop_type_match_failures++;
		}
		if (!run_caller_afva (core, caller_fcn)) {
			state->prop_afva_failures++;
		}
		state->prop_callers_updated++;
		callee_updates++;
	}

	free (callee_callers);
}

static char *format_sample_callees(char **sample_callees, size_t sample_count) {
	RStrBuf sb;
	char *out;
	size_t i;

	if (!sample_callees || sample_count == 0) {
		return strdup ("-");
	}
	r_strbuf_init (&sb);
	for (i = 0; i < sample_count; i++) {
		if (i > 0) {
			r_strbuf_append (&sb, ",");
		}
		r_strbuf_append (&sb, sample_callees[i]);
	}
	out = strdup (R_STRBUF_SAFEGET (&sb));
	r_strbuf_fini (&sb);
	return out ? out : strdup ("-");
}

static bool verify_practical_signature_consistency (
	RCore *core,
	const RJson *sig_root,
	bool check_signature,
	bool check_callconv,
	bool *afij_signature_drift
) {
	bool ok = true;
	char *afcfj_json = NULL;
	RJson *afcfj_root = NULL;
	const RJson *afcfj_item = NULL;
	char *afij_json = NULL;
	RJson *afij_root = NULL;
	const RJson *afij_item = NULL;
	const RJson *j_expected_signature;
	const RJson *j_expected_ret;
	const RJson *j_expected_params;
	const RJson *j_expected_callconv;

	if (afij_signature_drift) {
		*afij_signature_drift = false;
	}
	if (!core || !sig_root || sig_root->type != R_JSON_OBJECT) {
		return false;
	}

	j_expected_signature = r_json_get (sig_root, "signature");
	j_expected_ret = r_json_get (sig_root, "ret_type");
	j_expected_params = r_json_get (sig_root, "params");
	j_expected_callconv = r_json_get (sig_root, "callconv");

	if (check_signature) {
		const RJson *j_actual_ret;
		const RJson *j_actual_args;
		const RJson *expected_param;
		const RJson *actual_arg;

		afcfj_json = r_core_cmd_str (core, "afcfj");
		afcfj_root = afcfj_json ? r_json_parse (afcfj_json) : NULL;
		if (!afcfj_root || afcfj_root->type != R_JSON_ARRAY) {
			ok = false;
		} else {
			afcfj_item = json_next_object (afcfj_root->children.first);
			if (!afcfj_item) {
				ok = false;
			}
		}

		if (ok) {
			j_actual_ret = r_json_get (afcfj_item, "return");
			j_actual_args = r_json_get (afcfj_item, "args");

			if (!j_expected_ret || j_expected_ret->type != R_JSON_STRING
					|| !j_actual_ret || j_actual_ret->type != R_JSON_STRING) {
				ok = false;
			} else if (!strings_match_normalized (j_expected_ret->str_value, j_actual_ret->str_value)) {
				ok = false;
			}

			if (!j_expected_params || j_expected_params->type != R_JSON_ARRAY
					|| !j_actual_args || j_actual_args->type != R_JSON_ARRAY) {
				ok = false;
			} else {
				expected_param = json_next_object (j_expected_params->children.first);
				actual_arg = json_next_object (j_actual_args->children.first);
				while (expected_param && actual_arg) {
					const RJson *j_expected_type = r_json_get (expected_param, "type");
					const RJson *j_actual_type = r_json_get (actual_arg, "type");

					if (!j_expected_type || j_expected_type->type != R_JSON_STRING
							|| !j_actual_type || j_actual_type->type != R_JSON_STRING) {
						ok = false;
						break;
					}
					if (!strings_match_normalized (j_expected_type->str_value, j_actual_type->str_value)) {
						ok = false;
						break;
					}
					expected_param = json_next_object (expected_param->next);
					actual_arg = json_next_object (actual_arg->next);
				}
				if (expected_param || actual_arg) {
					ok = false;
				}
			}
		}
	}

	if (check_signature || check_callconv) {
		afij_json = r_core_cmd_str (core, "afij");
		afij_root = afij_json ? r_json_parse (afij_json) : NULL;
		if (!afij_root || afij_root->type != R_JSON_ARRAY) {
			if (check_callconv) {
				ok = false;
			}
		} else {
			afij_item = json_next_object (afij_root->children.first);
			if (!afij_item && check_callconv) {
				ok = false;
			}
		}
	}

	if (check_callconv && afij_item) {
		const RJson *j_afij_calltype = r_json_get (afij_item, "calltype");
		if (j_expected_callconv && j_expected_callconv->type == R_JSON_STRING
				&& j_expected_callconv->str_value && *j_expected_callconv->str_value) {
			if (!j_afij_calltype || j_afij_calltype->type != R_JSON_STRING
					|| !strings_match_normalized (j_expected_callconv->str_value, j_afij_calltype->str_value)) {
				ok = false;
			}
		}
	}

	if (check_signature && afij_item && afij_signature_drift) {
		const RJson *j_afij_sig = r_json_get (afij_item, "signature");
		if (!j_expected_signature || j_expected_signature->type != R_JSON_STRING
				|| !j_expected_signature->str_value || !*j_expected_signature->str_value) {
			*afij_signature_drift = false;
		} else if (!j_afij_sig || j_afij_sig->type != R_JSON_STRING) {
			*afij_signature_drift = true;
		} else if (!strings_match_normalized (j_expected_signature->str_value, j_afij_sig->str_value)) {
			*afij_signature_drift = true;
		}
	}

	r_json_free (afcfj_root);
	r_json_free (afij_root);
	free (afcfj_json);
	free (afij_json);
	return ok;
}

/* Eligibility/priority callback: score > 0 = eligible with priority, < 0 = ineligible */
static int sleigh_eligible(RAnal *anal) {
	R2ILContext *ctx = get_context (anal);
	return ctx ? 10 : -1;
}

/* Called at end of aaaa for global post-analysis passes */
static bool sleigh_post_analysis(RAnal *anal) {
	ensure_sleigh_pdd_core_plugin (anal);
	R2ILContext *ctx = get_context (anal);
	RCore *core;
	int xrefs_added = 0;
	int taint_comments = 0;
	int taint_flags = 0;
	int taint_xrefs = 0;
	int taint_parse_failures = 0;
	int taint_fcns_eligible = 0;
	int taint_fcns_skipped = 0;
	int taint_sink_hits = 0;
	int taint_risk_critical = 0;
	int taint_risk_high = 0;
	int taint_risk_medium = 0;
	int taint_risk_low = 0;
	int sig_fcns_considered = 0;
	int sig_fcns_skipped_arch = 0;
	int sig_fcns_skipped_size = 0;
	int sig_parse_failures = 0;
	int sig_cmd_failures = 0;
	int sig_skipped_low_conf = 0;
	int cc_skipped_low_conf = 0;
	int sig_signatures_updated = 0;
	int sig_cc_updated = 0;
	int consistency_verified = 0;
	int consistency_ok = 0;
	int consistency_mismatch = 0;
	int afij_signature_drift = 0;
	CallerPropagationState prop_state;
	int best_sink_rank = 1000;
	ut64 best_sink_addr = 0;
	ut64 focus_callee_addr = 0;
	char *best_sink_label = NULL;
	char *sample_callees = NULL;
	const char *arch_name = NULL;
	bool sig_arch_supported = false;

	if (!ctx) {
		return false;
	}
	core = anal->coreb.core;
	arch_name = r2il_arch_name (ctx);
	sig_arch_supported = is_signature_writeback_arch_supported (arch_name);
	if (core) {
		RAnalFunction *focus_fcn = r_anal_get_fcn_in (anal, core->addr, 0);
		if (focus_fcn) {
			focus_callee_addr = focus_fcn->addr;
		}
	}

	int num_fcns = r_list_length (anal->fcns);
	if (num_fcns == 0) {
		return true;
	}
	caller_propagation_state_init (&prop_state);

	R_LOG_INFO ("r2sleigh: post-analysis xref pass over %d functions", num_fcns);

	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, iter, fcn) {
		int bb_count = (fcn && fcn->bbs) ? r_list_length (fcn->bbs) : 0;
		bool taint_eligible = bb_count <= SLEIGH_TAINT_MAX_BLOCKS;
		const char *fcn_name = (fcn && fcn->name) ? fcn->name : "unknown";
		BlockArray blocks;
		char *json;
		RJson *root;

		if (taint_eligible) {
			taint_fcns_eligible++;
		} else {
			taint_fcns_skipped++;
		}

		if (!fcn || !lift_function_blocks (anal, fcn, ctx, &blocks)) {
			continue;
		}

		json = r2sleigh_get_data_refs (ctx,
			(const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr);
		if (!json || !*json) {
			r2il_string_free (json);
		} else {
			root = r_json_parse (json);
			if (!root || root->type != R_JSON_ARRAY) {
				r_json_free (root);
				r2il_string_free (json);
			} else {
				const RJson *item;
				for (item = root->children.first; item; item = item->next) {
					if (item->type != R_JSON_OBJECT) {
						continue;
					}
					const RJson *j_from = r_json_get (item, "from");
					const RJson *j_to = r_json_get (item, "to");
					const RJson *j_type = r_json_get (item, "type");
					if (!j_from || !j_to) {
						continue;
					}

					ut64 from = (ut64)j_from->num.u_value;
					ut64 to = (ut64)j_to->num.u_value;
					RAnalRefType type = R_ANAL_REF_TYPE_DATA;

					if (j_type && j_type->str_value) {
						switch (j_type->str_value[0]) {
						case 'c':
						case 'C':
							type = R_ANAL_REF_TYPE_CALL;
							break;
						case 'j':
						case 'J':
							type = R_ANAL_REF_TYPE_JUMP;
							break;
						case 's':
						case 'S':
							type = R_ANAL_REF_TYPE_STRN;
							break;
						default:
							type = R_ANAL_REF_TYPE_DATA;
						}
					}

					if (r_anal_xrefs_set (anal, from, to, type)) {
						xrefs_added++;
					}
				}
				r_json_free (root);
				r2il_string_free (json);
			}
		}

		/* Remove previous auto-generated taint artifacts for this function. */
		clear_taint_function_artifacts (anal, core, fcn, &blocks);

		if (taint_eligible) {
			char *taint_json = r2taint_function_summary_json (ctx,
				(const R2ILBlock **)blocks.blocks, blocks.count);
			if (taint_json && *taint_json) {
				RJson *taint_root = r_json_parse (taint_json);
				if (!taint_root || taint_root->type != R_JSON_OBJECT) {
					taint_parse_failures++;
					R_LOG_WARN ("r2sleigh: taint post-analysis parse failed for %s @ 0x%"PFMT64x,
						fcn_name, fcn->addr);
					r_json_free (taint_root);
				} else {
					const RJson *j_sources = r_json_get (taint_root, "sources");
					const RJson *j_sink_hits = r_json_get (taint_root, "sink_hits");
					TaintSourceMap source_map;
					TaintSummaryMap summaries;
					EdgeSet seen_edges;

					taint_source_map_init (&source_map);
					taint_summary_map_init (&summaries);
					edge_set_init (&seen_edges);

					if (j_sources && j_sources->type == R_JSON_ARRAY) {
						const RJson *src_item;
						for (src_item = j_sources->children.first; src_item; src_item = src_item->next) {
							const RJson *j_block;
							const RJson *j_labels;
							const RJson *label;
							ut64 src_block;

							if (src_item->type != R_JSON_OBJECT) {
								continue;
							}
							j_block = r_json_get (src_item, "block");
							j_labels = r_json_get (src_item, "labels");
							if (!j_block || !j_labels || j_labels->type != R_JSON_ARRAY) {
								continue;
							}
							src_block = (ut64)j_block->num.u_value;
							for (label = j_labels->children.first; label; label = label->next) {
								if (label->type == R_JSON_STRING && label->str_value) {
									taint_source_map_add (&source_map, label->str_value, src_block);
								}
							}
						}
					}

					if (!j_sink_hits || j_sink_hits->type != R_JSON_ARRAY) {
						taint_parse_failures++;
						R_LOG_WARN ("r2sleigh: taint sink_hits missing/invalid for %s @ 0x%"PFMT64x,
							fcn_name, fcn->addr);
					} else {
						const RJson *hit_item;
						for (hit_item = j_sink_hits->children.first; hit_item; hit_item = hit_item->next) {
							const RJson *j_block;
							const RJson *j_op;
							const RJson *j_tainted_vars;
							const RJson *tv_item;
							const char *op_name = NULL;
							char **sink_labels = NULL;
							size_t sink_label_count = 0;
							size_t sink_label_cap = 0;
							size_t li;
							ut64 sink_block;
							bool is_call_sink = false;
							bool had_primary_sources = false;
							bool added_nonself = false;

							if (hit_item->type != R_JSON_OBJECT) {
								continue;
							}

							j_block = r_json_get (hit_item, "block");
							j_op = r_json_get (hit_item, "op");
							j_tainted_vars = r_json_get (hit_item, "tainted_vars");
							if (!j_block || !j_tainted_vars || j_tainted_vars->type != R_JSON_ARRAY) {
								continue;
							}
							sink_block = (ut64)j_block->num.u_value;

							if (j_op && j_op->type == R_JSON_OBJECT) {
								const RJson *j_op_name = r_json_get (j_op, "op");
								if (j_op_name && j_op_name->type == R_JSON_STRING && j_op_name->str_value) {
									op_name = j_op_name->str_value;
								}
							}
							is_call_sink = op_name && (!strcmp (op_name, "Call") || !strcmp (op_name, "CallInd"));

							for (tv_item = j_tainted_vars->children.first; tv_item; tv_item = tv_item->next) {
								const RJson *j_labels;
								const RJson *label;
								if (tv_item->type != R_JSON_OBJECT) {
									continue;
								}
								j_labels = r_json_get (tv_item, "labels");
								if (!j_labels || j_labels->type != R_JSON_ARRAY) {
									continue;
								}
								for (label = j_labels->children.first; label; label = label->next) {
									if (label->type != R_JSON_STRING || !label->str_value) {
										continue;
									}
									if (is_noisy_taint_label (label->str_value)) {
										continue;
									}
									append_unique_string (&sink_labels, &sink_label_count, &sink_label_cap, label->str_value);
								}
							}

							taint_sink_hits++;
							TaintBlockSummary *summary = taint_summary_map_get_or_add (&summaries, sink_block);
							if (summary) {
								summary->hits++;
								if (is_call_sink) {
									summary->call_hits++;
								}
								if (op_name && !strcmp (op_name, "Store")) {
									summary->store_hits++;
								}
								if (is_call_sink && j_op && j_op->type == R_JSON_OBJECT) {
									char *call_name = resolve_call_target_name (core, anal, j_op);
									if (call_name) {
										taint_summary_add_call_name (summary, call_name);
										free (call_name);
									}
								}
							}

							if (sink_label_count == 0) {
								free_string_array (sink_labels, sink_label_count);
								continue;
							}

							if (summary) {
								for (li = 0; li < sink_label_count; li++) {
									taint_summary_add_label (summary, sink_labels[li]);
								}
							}

							for (li = 0; li < sink_label_count; li++) {
								const TaintLabelSource *srcs = taint_source_map_find (&source_map, sink_labels[li]);
								size_t si;
								if (!srcs || srcs->count == 0) {
									continue;
								}
								had_primary_sources = true;
								for (si = 0; si < srcs->count; si++) {
									ut64 src_block = srcs->blocks[si];
									if (src_block == sink_block) {
										continue;
									}
									if (maybe_add_taint_xref (anal, &seen_edges, src_block, sink_block, R_ANAL_REF_TYPE_DATA, &taint_xrefs)) {
										added_nonself = true;
									}
								}
							}

							if (had_primary_sources && !added_nonself && sink_block != fcn->addr) {
								maybe_add_taint_xref (anal, &seen_edges, fcn->addr, sink_block, R_ANAL_REF_TYPE_DATA, &taint_xrefs);
							}

							free_string_array (sink_labels, sink_label_count);
						}
					}

					size_t si;
					char **function_call_names = NULL;
					size_t function_ncall_names = 0;
					size_t function_call_name_cap = 0;
					char **function_labels = NULL;
					size_t function_nlabels = 0;
					size_t function_label_cap = 0;
					int function_call_hits = 0;
					int function_store_hits = 0;
					bool function_meaningful = false;
					bool function_has_dangerous_call = false;
					for (si = 0; si < summaries.count; si++) {
						TaintBlockSummary *summary = &summaries.items[si];
						char *comment = format_taint_summary_comment (summary);
						size_t li;
						if (comment && *comment) {
							set_sla_taint_comment_line (anal, summary->addr, comment);
							taint_comments++;

							if (core && core->flags) {
								char flag_name[160];
								snprintf (flag_name, sizeof (flag_name),
									"sla.taint.fcn_%"PFMT64x".blk_%"PFMT64x, fcn->addr, summary->addr);
								if (r_flag_set (core->flags, flag_name, summary->addr, 1)) {
									taint_flags++;
								}
							}
						}

						if (summary->labels && summary->nlabels > 0) {
							int rank = label_rank (summary->labels[0]);
							function_meaningful = true;
							function_call_hits += summary->call_hits;
							function_store_hits += summary->store_hits;

							for (li = 0; li < summary->nlabels; li++) {
								append_unique_string (&function_labels, &function_nlabels, &function_label_cap, summary->labels[li]);
							}
							for (li = 0; li < summary->ncall_names; li++) {
								append_unique_string (&function_call_names, &function_ncall_names, &function_call_name_cap, summary->call_names[li]);
								if (is_dangerous_sink (summary->call_names[li])) {
									function_has_dangerous_call = true;
								}
							}

							if (rank < best_sink_rank) {
								free (best_sink_label);
								best_sink_label = strdup (summary->labels[0]);
								best_sink_addr = summary->addr;
								best_sink_rank = rank;
							}
						}
						free (comment);
					}
					{
						TaintRiskLevel risk_level = classify_taint_risk (
							function_meaningful,
							function_has_dangerous_call,
							function_call_hits,
							function_store_hits
						);
						char *risk_comment = format_taint_risk_comment (
							risk_level,
							function_call_names,
							function_ncall_names,
							function_call_hits,
							function_store_hits,
							function_labels,
							function_nlabels
						);

						switch (risk_level) {
						case TAINT_RISK_CRITICAL:
							taint_risk_critical++;
							break;
						case TAINT_RISK_HIGH:
							taint_risk_high++;
							break;
						case TAINT_RISK_MEDIUM:
							taint_risk_medium++;
							break;
						case TAINT_RISK_LOW:
							taint_risk_low++;
							break;
						case TAINT_RISK_NONE:
						default:
							break;
						}

						if (risk_comment && *risk_comment) {
							set_sla_taint_risk_comment_line (anal, fcn->addr, risk_comment);
							taint_comments++;
						}
						free (risk_comment);

						if (risk_level != TAINT_RISK_NONE && core && core->flags) {
							char risk_flag[192];
							snprintf (risk_flag, sizeof (risk_flag),
								"sla.taint.risk.%s.fcn_%"PFMT64x,
								taint_risk_level_flag_name (risk_level), fcn->addr);
							if (r_flag_set (core->flags, risk_flag, fcn->addr, 1)) {
								taint_flags++;
							}
						}
					}
					free_string_array (function_call_names, function_ncall_names);
					free_string_array (function_labels, function_nlabels);

					edge_set_free (&seen_edges);
					taint_summary_map_free (&summaries);
					taint_source_map_free (&source_map);
					r_json_free (taint_root);
				}
			}
			r2il_string_free (taint_json);
		}

		if (!sig_arch_supported || !core) {
			sig_fcns_skipped_arch++;
		} else if (bb_count > SLEIGH_SIG_WRITEBACK_MAX_BLOCKS) {
			sig_fcns_skipped_size++;
		} else {
			char *sig_json;
			RJson *sig_root;
			const RJson *j_signature;
			const RJson *j_callconv;
			const RJson *j_confidence;
			int confidence = 0;
			bool signature_applied = false;
			bool cc_applied = false;
			bool signature_drift = false;
			sig_fcns_considered++;

			sig_json = r2sleigh_infer_signature_cc_json (ctx,
				(const R2ILBlock **)blocks.blocks, blocks.count, fcn->addr, fcn->name);
			if (!sig_json || !*sig_json) {
				sig_parse_failures++;
				r2il_string_free (sig_json);
			} else {
				sig_root = r_json_parse (sig_json);
				if (!sig_root || sig_root->type != R_JSON_OBJECT) {
					sig_parse_failures++;
					r_json_free (sig_root);
					r2il_string_free (sig_json);
				} else {
					j_signature = r_json_get (sig_root, "signature");
					j_callconv = r_json_get (sig_root, "callconv");
					j_confidence = r_json_get (sig_root, "confidence");
					if (j_confidence && j_confidence->type == R_JSON_INTEGER) {
						confidence = (int)j_confidence->num.u_value;
					}

						if (j_signature && j_signature->type == R_JSON_STRING
								&& j_signature->str_value && *j_signature->str_value) {
							if (confidence < SLEIGH_SIG_MIN_CONFIDENCE) {
								sig_skipped_low_conf++;
							} else if (apply_inferred_signature (anal, core, fcn, j_signature->str_value)) {
								sig_signatures_updated++;
								signature_applied = true;
								propagate_signature_to_direct_callers (anal, core, fcn->addr, fcn_name,
									&prop_state, focus_callee_addr && fcn->addr == focus_callee_addr);
							} else {
								sig_cmd_failures++;
								R_LOG_WARN ("r2sleigh: signature write-back failed for %s @ 0x%"PFMT64x,
									fcn_name, fcn->addr);
							}
						} else {
							sig_parse_failures++;
						}

					if (j_callconv && j_callconv->type == R_JSON_STRING
							&& j_callconv->str_value && *j_callconv->str_value) {
						if (confidence < SLEIGH_CC_MIN_CONFIDENCE) {
							cc_skipped_low_conf++;
						} else if (apply_inferred_callconv (anal, core, fcn, j_callconv->str_value)) {
							sig_cc_updated++;
							cc_applied = true;
						} else {
							sig_cmd_failures++;
							R_LOG_WARN ("r2sleigh: calling-convention write-back failed for %s @ 0x%"PFMT64x,
								fcn_name, fcn->addr);
						}
					}

					if (signature_applied || cc_applied) {
						consistency_verified++;
						if (verify_practical_signature_consistency (
								core, sig_root, signature_applied, cc_applied, &signature_drift)) {
							consistency_ok++;
						} else {
							consistency_mismatch++;
						}
						if (signature_drift) {
							afij_signature_drift++;
						}
					}

					r_json_free (sig_root);
					r2il_string_free (sig_json);
				}
			}
		}

		block_array_free (&blocks);
	}

	R_LOG_INFO ("r2sleigh: post-analysis added %d xrefs", xrefs_added);
	R_LOG_INFO ("r2sleigh: post-analysis taint eligible=%d skipped=%d comments=%d flags=%d xrefs=%d sink_hits=%d parse_failures=%d",
		taint_fcns_eligible, taint_fcns_skipped, taint_comments, taint_flags, taint_xrefs,
		taint_sink_hits, taint_parse_failures);
	R_LOG_INFO ("r2sleigh: post-analysis risk summary: critical=%d high=%d medium=%d low=%d",
		taint_risk_critical, taint_risk_high, taint_risk_medium, taint_risk_low);
	R_LOG_INFO ("r2sleigh: signature write-back considered=%d skipped_arch=%d skipped_size=%d parse_failures=%d command_failures=%d signatures_updated=%d cc_updated=%d sig_low_conf_skips=%d cc_low_conf_skips=%d consistency_verified=%d consistency_ok=%d consistency_mismatch=%d afij_signature_drift=%d",
		sig_fcns_considered, sig_fcns_skipped_arch, sig_fcns_skipped_size, sig_parse_failures,
		sig_cmd_failures, sig_signatures_updated, sig_cc_updated, sig_skipped_low_conf,
		cc_skipped_low_conf, consistency_verified, consistency_ok, consistency_mismatch,
		afij_signature_drift);
	sample_callees = format_sample_callees (prop_state.sample_callees, prop_state.sample_callees_count);
	R_LOG_INFO ("r2sleigh: caller propagation prop_callees_triggered=%d prop_callees_skipped_cap=%d prop_callers_considered=%d prop_callers_updated=%d prop_callers_dedup_skipped=%d prop_callers_missing_fcn=%d prop_callers_per_callee_cap_skipped=%d prop_callers_total_cap_skipped=%d prop_type_match_failures=%d prop_afva_failures=%d sample_callees=%s",
		prop_state.prop_callees_triggered, prop_state.prop_callees_skipped_cap,
		prop_state.prop_callers_considered, prop_state.prop_callers_updated,
		prop_state.prop_callers_dedup_skipped, prop_state.prop_callers_missing_fcn,
		prop_state.prop_callers_per_callee_cap_skipped, prop_state.prop_callers_total_cap_skipped,
		prop_state.prop_type_match_failures, prop_state.prop_afva_failures,
		sample_callees ? sample_callees : "-");
	free (sample_callees);
	caller_propagation_state_fini (&prop_state);
	if (best_sink_label) {
		R_LOG_INFO ("r2sleigh: post-analysis most interesting sink 0x%"PFMT64x" label=%s",
			best_sink_addr, best_sink_label);
		free (best_sink_label);
	}
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
	.eligible = sleigh_eligible,
	.op = sleigh_op,
	.cmd = sleigh_cmd,
	/* Deep integration callbacks */
	.analyze_fcn = sleigh_analyze_fcn,
	.recover_vars = sleigh_recover_vars,
	.get_data_refs = sleigh_get_data_refs,
	.post_analysis = sleigh_post_analysis,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sleigh,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
