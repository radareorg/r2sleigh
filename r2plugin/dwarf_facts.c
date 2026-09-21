/* r2sleigh - LGPL - Copyright 2026 */
/* Read the two pieces of DWARF evidence r2sleigh needs from the debug
 * information itself, rather than from a side table the fork maintained.
 *
 * See dwarf_facts.h for why. The walk itself lives in Rust, in
 * `crates/r2image/src/debug.rs`, which is the same reader the engine uses when
 * it opens a binary without radare2. This carried a second one -- a DIE walk
 * over radare2's parsed debug information -- and two readers of one format
 * disagree eventually. radare2 has the sections; this hands the bytes over. */

#include "dwarf_facts.h"

#include <r_bin.h>
#include <r_util.h>

/* The reader's own entry points, exported by the engine's shared object. */
typedef struct {
	const char *name;
	const ut8 *data;
	size_t len;
} R2SleighDwarfSectionV2;

extern size_t r2sleigh_dwarf_section_count_v2(void);
extern const char *r2sleigh_dwarf_section_name_v2(size_t index);
extern void *r2sleigh_dwarf_open_v2(const R2SleighDwarfSectionV2 *sections,
	size_t count, bool big_endian);
extern void r2sleigh_dwarf_close_v2(void *facts);
extern const char *r2sleigh_dwarf_frame_base_register_v2(const void *facts,
	ut64 function_addr, const char *arch, ut32 bits);
extern int32_t r2sleigh_dwarf_formal_ordinal_v2(const void *facts,
	ut64 function_addr, const char *name);

typedef struct {
	/* What the cache was built from. A different binary, or the same binary
	 * reloaded, is a different cache: the address alone is not enough, a
	 * freed RBinFile can be replaced at the same address. */
	const void *bin_file;
	ut64 baddr;
	ut64 obj_id;
	bool parsed;
	void *facts;
} R2SleighDwarfCache;

static R2SleighDwarfCache dwarf_cache;
static RThreadLock *dwarf_cache_lock;

static void dwarf_cache_clear(void) {
	if (dwarf_cache.facts) {
		r2sleigh_dwarf_close_v2 (dwarf_cache.facts);
		dwarf_cache.facts = NULL;
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

static ut64 dwarf_cache_object_id(RBinFile *bf) {
	return bf && bf->bo? (ut64)(size_t)bf->bo: UT64_MAX;
}

/* One named section's bytes, read from the file rather than from memory: the
 * debug sections are not loaded, so nothing maps them. */
static ut8 *dwarf_section_bytes(RBinFile *bf, const char *name, R_OUT size_t *len) {
	*len = 0;
	if (!bf || !bf->bo) {
		return NULL;
	}
	RVecRBinSection *sections = r_bin_file_get_sections_vec (bf);
	if (!sections) {
		return NULL;
	}
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		if (!section->name || strcmp (section->name, name)) {
			continue;
		}
		if (!section->size || section->size > ST32_MAX) {
			return NULL;
		}
		ut8 *bytes = malloc (section->size);
		if (!bytes) {
			return NULL;
		}
		if (r_buf_read_at (bf->buf, section->paddr, bytes, section->size) < 1) {
			free (bytes);
			return NULL;
		}
		*len = (size_t)section->size;
		return bytes;
	}
	return NULL;
}

/* Read the debug information once per binary, on the first question asked
 * about it. A miss is cached as an absent handle, so a binary with no debug
 * information is not reread for every function. */
static void *dwarf_cache_facts(RAnal *anal) {
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
		return dwarf_cache.facts;
	}
	dwarf_cache_clear ();
	dwarf_cache.bin_file = bf;
	dwarf_cache.baddr = baddr;
	dwarf_cache.obj_id = obj_id;
	dwarf_cache.parsed = true;

	const size_t wanted = r2sleigh_dwarf_section_count_v2 ();
	if (!wanted) {
		return NULL;
	}
	R2SleighDwarfSectionV2 *sections = R_NEWS0 (R2SleighDwarfSectionV2, wanted);
	if (!sections) {
		return NULL;
	}
	size_t count = 0;
	size_t index;
	for (index = 0; index < wanted; index++) {
		const char *name = r2sleigh_dwarf_section_name_v2 (index);
		if (!name) {
			continue;
		}
		size_t len = 0;
		ut8 *bytes = dwarf_section_bytes (bf, name, &len);
		if (!bytes) {
			continue;
		}
		sections[count].name = name;
		sections[count].data = bytes;
		sections[count].len = len;
		count++;
	}
	if (count) {
		const bool big_endian = bf->bo->info && bf->bo->info->big_endian;
		dwarf_cache.facts = r2sleigh_dwarf_open_v2 (sections, count, big_endian);
	}
	for (index = 0; index < count; index++) {
		free ((void *)sections[index].data);
	}
	free (sections);
	return dwarf_cache.facts;
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
	if (!anal || !anal->config) {
		return false;
	}
	if (!dwarf_cache_lock) {
		dwarf_cache_lock = r_th_lock_new (false);
		if (!dwarf_cache_lock) {
			return false;
		}
	}
	r_th_lock_enter (dwarf_cache_lock);
	void *facts = dwarf_cache_facts (anal);
	bool found = false;
	const char *name = facts
		? r2sleigh_dwarf_frame_base_register_v2 (facts, function_addr,
			r_str_get (anal->config->arch), (ut32)anal->config->bits)
		: NULL;
	if (name) {
		/* The register has to exist on the profile in use, or the name proves
		 * nothing about this machine. */
		RRegItem *reg = anal->reg? r_reg_get (anal->reg, name, -1): NULL;
		if (reg && reg->offset >= 0 && reg->size > 0) {
			base->name = strdup (name);
			if (base->name) {
				base->offset = (ut64)reg->offset;
				base->size = (ut32)reg->size;
				found = true;
			}
		}
		r_unref (reg);
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
	void *facts = dwarf_cache_facts (anal);
	const int32_t position = facts
		? r2sleigh_dwarf_formal_ordinal_v2 (facts, function_addr, name): -1;
	r_th_lock_leave (dwarf_cache_lock);
	if (position < 0) {
		return false;
	}
	*ordinal = (int)position;
	return true;
}
