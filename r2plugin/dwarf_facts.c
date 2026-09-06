/* r2sleigh - LGPL - Copyright 2026 */
/* Read the two pieces of DWARF evidence r2sleigh needs from the debug
 * information itself, rather than from a side table the fork maintained.
 *
 * See dwarf_facts.h for why. The shape of the walk mirrors radare2's own
 * importer: a compilation unit holds its debug information entries in one
 * flat vector in document order, and `has_children` marks where nesting
 * begins, so a subprogram's formals are the entries that follow it until its
 * children are exhausted. */

#include "dwarf_facts.h"

#include <r_bin.h>
#include <r_bin_dwarf.h>
#include <r_util.h>

typedef struct {
	ut64 addr;
	char *frame_base_reg;
	/* Formal parameter names in the order the caller passes them. An unnamed
	 * formal keeps its position with a NULL entry, because it still shifts
	 * the ones after it. */
	char **formals;
	size_t formal_count;
} R2SleighDwarfFunction;

typedef struct {
	/* What the cache was built from. A different binary, or the same binary
	 * reloaded, invalidates it: the pointer alone is not enough, because a
	 * freed RBinFile can be replaced at the same address. */
	const void *bin_file;
	ut64 baddr;
	ut64 obj_id;
	HtUP *by_addr; /* function address => R2SleighDwarfFunction * */
	bool parsed;
} R2SleighDwarfCache;

static R2SleighDwarfCache dwarf_cache;
static RThreadLock *dwarf_cache_lock;

static void dwarf_function_free(R2SleighDwarfFunction *function) {
	if (!function) {
		return;
	}
	size_t index;
	for (index = 0; index < function->formal_count; index++) {
		free (function->formals[index]);
	}
	free (function->formals);
	free (function->frame_base_reg);
	free (function);
}

static void dwarf_function_kv_free(HtUPKv *kv) {
	if (kv) {
		dwarf_function_free (kv->value);
	}
}

static void dwarf_cache_clear(void) {
	if (dwarf_cache.by_addr) {
		ht_up_free (dwarf_cache.by_addr);
		dwarf_cache.by_addr = NULL;
	}
	dwarf_cache.bin_file = NULL;
	dwarf_cache.baddr = UT64_MAX;
	dwarf_cache.obj_id = UT64_MAX;
	dwarf_cache.parsed = false;
}

R_API void r2sleigh_dwarf_facts_reset(void) {
	if (!dwarf_cache_lock) {
		dwarf_cache_clear ();
		return;
	}
	r_th_lock_enter (dwarf_cache_lock);
	dwarf_cache_clear ();
	r_th_lock_leave (dwarf_cache_lock);
}

static const RBinDwarfAttrValue *dwarf_attr(const RBinDwarfDie *die, ut64 name) {
	if (!die || !die->attr_values) {
		return NULL;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == name) {
			return value;
		}
	}
	return NULL;
}

static const char *dwarf_attr_string(const RBinDwarfDie *die, ut64 name) {
	const RBinDwarfAttrValue *value = dwarf_attr (die, name);
	if (!value || value->kind != DW_AT_KIND_STRING) {
		return NULL;
	}
	return value->string.content;
}

static bool dwarf_attr_address(const RBinDwarfDie *die, ut64 name, R_OUT ut64 *addr) {
	const RBinDwarfAttrValue *value = dwarf_attr (die, name);
	if (!value) {
		return false;
	}
	switch (value->kind) {
	case DW_AT_KIND_ADDRESS:
		*addr = value->address;
		return true;
	case DW_AT_KIND_CONSTANT:
		*addr = value->uconstant;
		return true;
	default:
		return false;
	}
}

/* The base-pointer register a DWARF register number names.
 *
 * Only the architectures r2sleigh lifts are answered, and only their frame
 * pointer: this exists to confirm that the debug information's frame base is
 * the machine's base pointer, not to translate register numbers in general.
 * Anything else answers absent, which is what the caller wants -- an
 * unrecognized frame base is evidence of nothing rather than a guess. */
static const char *dwarf_frame_base_register(const char *arch, int bits, ut64 reg_num) {
	if (R_STR_ISEMPTY (arch)) {
		return NULL;
	}
	if (!strcmp (arch, "x86") && bits == 64) {
		return reg_num == 6? "rbp": NULL;
	}
	if (!strcmp (arch, "x86") && bits == 32) {
		return reg_num == 5? "ebp": NULL;
	}
	if (!strcmp (arch, "arm") && bits == 64) {
		return reg_num == 29? "x29": NULL;
	}
	return NULL;
}

static char *dwarf_die_frame_base_register(RAnal *anal, const RBinDwarfDie *die) {
	const RBinDwarfAttrValue *frame_base = dwarf_attr (die, DW_AT_frame_base);
	if (!frame_base || frame_base->kind != DW_AT_KIND_BLOCK
		|| !frame_base->block.data || frame_base->block.length != 1) {
		return NULL;
	}
	const ut8 op = frame_base->block.data[0];
	if (op < DW_OP_reg0 || op > DW_OP_reg31) {
		return NULL;
	}
	if (!anal->config || anal->config->bits <= 0) {
		return NULL;
	}
	const char *name = dwarf_frame_base_register (anal->config->arch,
		anal->config->bits, op - DW_OP_reg0);
	if (!name) {
		return NULL;
	}
	// The register has to exist on the profile in use, or the name proves
	// nothing about this machine.
	if (!anal->reg || !r_reg_get (anal->reg, name, -1)) {
		return NULL;
	}
	return strdup (name);
}

/* Walk one compilation unit, recording every subprogram that has an entry
 * address. `dies` is in document order; `has_children` opens a level and the
 * null entry (tag zero) closes it, which is how the importer walks it too. */
static void dwarf_collect_unit(RAnal *anal, RBinDwarfCompUnit *unit, HtUP *by_addr) {
	if (!unit || !unit->dies) {
		return;
	}
	R2SleighDwarfFunction *current = NULL;
	int depth = 0;
	int function_depth = -1;
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		if (die->tag == 0) {
			// A null entry closes the innermost open level.
			if (depth > 0) {
				depth--;
			}
			if (current && depth <= function_depth) {
				current = NULL;
				function_depth = -1;
			}
			continue;
		}
		if (die->tag == DW_TAG_subprogram) {
			ut64 low_pc = 0;
			current = NULL;
			function_depth = -1;
			if (dwarf_attr_address (die, DW_AT_low_pc, &low_pc) && low_pc) {
				R2SleighDwarfFunction *function = R_NEW0 (R2SleighDwarfFunction);
				if (function) {
					function->addr = low_pc;
					function->frame_base_reg =
						dwarf_die_frame_base_register (anal, die);
					if (ht_up_update (by_addr, low_pc, function)) {
						current = function;
						function_depth = depth;
					} else {
						dwarf_function_free (function);
					}
				}
			}
		} else if (current && die->tag == DW_TAG_formal_parameter
			&& depth == function_depth + 1) {
			// Every formal the caller passes occupies a position, named or
			// not: an unnamed one still shifts the ones after it.
			const char *name = dwarf_attr_string (die, DW_AT_name);
			char **grown = realloc (current->formals,
				(current->formal_count + 1) * sizeof (*grown));
			if (grown) {
				current->formals = grown;
				current->formals[current->formal_count] =
					name? strdup (name): NULL;
				current->formal_count++;
			}
		}
		if (die->has_children) {
			depth++;
		}
	}
}

static ut64 dwarf_cache_object_id(RBinFile *bf) {
	return bf && bf->bo? (ut64)(size_t)bf->bo: UT64_MAX;
}

/* Parse the debug information once per binary, on the first question asked
 * about it. A miss is cached as an empty table, so a binary with no debug
 * information is not reparsed for every function. */
static HtUP *dwarf_cache_table(RAnal *anal) {
	if (!anal || !anal->binb.bin) {
		return NULL;
	}
	RBin *bin = anal->binb.bin;
	RBinFile *bf = r_bin_cur (bin);
	if (!bf) {
		return NULL;
	}
	const ut64 baddr = r_bin_get_baddr (bin);
	const ut64 obj_id = dwarf_cache_object_id (bf);
	if (dwarf_cache.parsed && dwarf_cache.bin_file == (const void *)bf
		&& dwarf_cache.baddr == baddr && dwarf_cache.obj_id == obj_id) {
		return dwarf_cache.by_addr;
	}
	dwarf_cache_clear ();
	dwarf_cache.bin_file = bf;
	dwarf_cache.baddr = baddr;
	dwarf_cache.obj_id = obj_id;
	dwarf_cache.parsed = true;
	dwarf_cache.by_addr = ht_up_new (NULL, dwarf_function_kv_free, NULL);
	if (!dwarf_cache.by_addr) {
		return NULL;
	}
	// `R_MODE_PRINT` is zero, so the mode has to be spelled: a parse asked for
	// quietly still writes both tables to stdout otherwise, straight into the
	// middle of the decompiler's output.
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, R_MODE_SET);
	if (!abbrevs) {
		return dwarf_cache.by_addr;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, R_MODE_SET);
	if (info) {
		if (info->comp_units) {
			RBinDwarfCompUnit *unit;
			R_VEC_FOREACH (info->comp_units, unit) {
				dwarf_collect_unit (anal, unit, dwarf_cache.by_addr);
			}
		}
		r_bin_dwarf_free_debug_info (info);
	}
	r_bin_dwarf_free_debug_abbrev (abbrevs);
	return dwarf_cache.by_addr;
}

static R2SleighDwarfFunction *dwarf_function_at(RAnal *anal, ut64 function_addr) {
	HtUP *table = dwarf_cache_table (anal);
	return table? ht_up_find (table, function_addr, NULL): NULL;
}

R_API void r2sleigh_dwarf_frame_base_fini(R2SleighDwarfFrameBase *base) {
	if (base) {
		R_FREE (base->name);
		base->offset = 0;
		base->size = 0;
	}
}

R_API bool r2sleigh_dwarf_function_frame_base(RAnal *anal, ut64 function_addr,
		R_OUT R2SleighDwarfFrameBase *base) {
	R_RETURN_VAL_IF_FAIL (base, false);
	memset (base, 0, sizeof (*base));
	if (!anal) {
		return false;
	}
	if (!dwarf_cache_lock) {
		dwarf_cache_lock = r_th_lock_new (false);
		if (!dwarf_cache_lock) {
			return false;
		}
	}
	r_th_lock_enter (dwarf_cache_lock);
	R2SleighDwarfFunction *function = dwarf_function_at (anal, function_addr);
	bool found = false;
	if (function && function->frame_base_reg) {
		RRegItem *reg = anal->reg
			? r_reg_get (anal->reg, function->frame_base_reg, -1): NULL;
		if (reg && reg->offset >= 0 && reg->size > 0) {
			base->name = strdup (function->frame_base_reg);
			if (base->name) {
				base->offset = (ut64)reg->offset;
				base->size = (ut32)reg->size;
				found = true;
			}
		}
	}
	r_th_lock_leave (dwarf_cache_lock);
	return found;
}

R_API bool r2sleigh_dwarf_formal_ordinal(RAnal *anal, ut64 function_addr,
		const char *name, R_OUT int *ordinal) {
	R_RETURN_VAL_IF_FAIL (ordinal, false);
	*ordinal = -1;
	if (!anal || R_STR_ISEMPTY (name)) {
		return false;
	}
	if (!dwarf_cache_lock) {
		dwarf_cache_lock = r_th_lock_new (false);
		if (!dwarf_cache_lock) {
			return false;
		}
	}
	r_th_lock_enter (dwarf_cache_lock);
	R2SleighDwarfFunction *function = dwarf_function_at (anal, function_addr);
	bool found = false;
	if (function) {
		// One name, one position. A repeated formal name describes nothing
		// this can certify, so it answers absent rather than picking the
		// first.
		size_t index;
		int match = -1;
		for (index = 0; index < function->formal_count; index++) {
			const char *formal = function->formals[index];
			if (!formal || strcmp (formal, name)) {
				continue;
			}
			if (match >= 0) {
				match = -1;
				break;
			}
			match = (int)index;
		}
		if (match >= 0) {
			*ordinal = match;
			found = true;
		}
	}
	r_th_lock_leave (dwarf_cache_lock);
	return found;
}
