/* r2sleigh - LGPL - Copyright 2026 */
/* Facts read from the binary's own debug information entries.
 *
 * radare2's DWARF importer turns debug information into its analysis model:
 * variables with deltas, prototypes, types. What it does not keep is the
 * evidence behind that model -- which formal a stack home is, in the order the
 * caller passes them, and which register the debug information names as the
 * frame base. r2sleigh needs the evidence rather than the conclusion, because
 * a certificate has to say where a fact came from.
 *
 * Those two facts used to be recorded by the fork, in side tables hanging off
 * `RAnal`. They are read here instead, from the same entries radare2 reads,
 * through the public `r_bin_dwarf_*` API. The debug information is parsed
 * twice as a result, once by radare2 and once here, which is the price of the
 * fork not carrying r2sleigh's evidence model. */

#ifndef R2SLEIGH_DWARF_FACTS_H
#define R2SLEIGH_DWARF_FACTS_H

#include <r_anal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The register the debug information names as this function's frame base,
 * when it names one plainly.
 *
 * Only a frame base that is a single `DW_OP_regN` naming the architecture's
 * base pointer answers. A base computed from the call frame address, which is
 * what most optimized code carries, is not a register and leaves this absent
 * rather than guessed. */
typedef struct r2sleigh_dwarf_frame_base_t {
	char *name;
	ut64 offset;
	ut32 size;
} R2SleighDwarfFrameBase;

R_API void r2sleigh_dwarf_frame_base_fini(R2SleighDwarfFrameBase *base);

/* Whether the debug information gives this function a plain register frame
 * base, and which register it is. */
R_API bool r2sleigh_dwarf_function_frame_base(RAnal *anal, ut64 function_addr,
	R_OUT R2SleighDwarfFrameBase *base);

/* The position of `name` in this function's formal parameter list, counting
 * every parameter the caller passes.
 *
 * This is the ABI position, not radare2's dense argument index: a formal the
 * importer could not place still occupies a position here, which is the whole
 * reason the two can disagree and the reason this is worth asking. */
R_API bool r2sleigh_dwarf_formal_ordinal(RAnal *anal, ut64 function_addr,
	const char *name, R_OUT int *ordinal);

/* Drop the parsed debug information. Called when the analysis session ends;
 * the cache is otherwise keyed on the binary file and rebuilt when it
 * changes. */
R_API void r2sleigh_dwarf_facts_reset(void);

#ifdef __cplusplus
}
#endif

#endif
