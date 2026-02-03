/* radare2 - LGPL - Copyright 2025 - r2sleigh project */

#include <r_arch.h>
#include <r_anal.h>
#include "r2sleigh_plugin.h"

static char *sleigh_arch_regs(RArchSession *as) {
	/* Get the analysis context from the arch session user data */
	RAnal *anal = (RAnal *)as->user;
	if (!anal) {
		/* Return minimal x86-64 profile as fallback */
		const char *profile = "gpr\trax\t.64\t0\t0\n\
gpr\trbx\t.64\t1\t0\n\
gpr\trcx\t.64\t2\t0\n\
gpr\trdx\t.64\t3\t0\n\
gpr\trsi\t.64\t4\t0\n\
gpr\trdi\t.64\t5\t0\n\
gpr\tr8\t.64\t6\t0\n\
gpr\tr9\t.64\t7\t0\n\
gpr\tr10\t.64\t8\t0\n\
gpr\tr11\t.64\t9\t0\n\
gpr\tr12\t.64\t10\t0\n\
gpr\tr13\t.64\t11\t0\n\
gpr\tr14\t.64\t12\t0\n\
gpr\tr15\t.64\t13\t0\n\
gpr\trsp\t.64\t14\t0\n\
gpr\trbp\t.64\t15\t0\n\
gpr\trip\t.64\t16\t0\n\
=PC\trip\n\
=SP\trsp\n\
=BP\trbp\n\
=R0\trax\n\
=A0\trdi\n\
=A1\trsi\n\
=A2\trdx\n\
=A3\trcx\n";
		return strdup (profile);
	}

	/* Try to get register profile from r2sleigh context */
	R2ILContext *ctx = get_context (anal);
	if (!ctx) {
		/* Return minimal x86-64 profile as fallback */
		const char *profile = "gpr\trax\t.64\t0\t0\n\
gpr\trbx\t.64\t1\t0\n\
gpr\trcx\t.64\t2\t0\n\
gpr\trdx\t.64\t3\t0\n\
gpr\trsi\t.64\t4\t0\n\
gpr\trdi\t.64\t5\t0\n\
gpr\tr8\t.64\t6\t0\n\
gpr\tr9\t.64\t7\t0\n\
gpr\tr10\t.64\t8\t0\n\
gpr\tr11\t.64\t9\t0\n\
gpr\tr12\t.64\t10\t0\n\
gpr\tr13\t.64\t11\t0\n\
gpr\tr14\t.64\t12\t0\n\
gpr\tr15\t.64\t13\t0\n\
gpr\trsp\t.64\t14\t0\n\
gpr\trbp\t.64\t15\t0\n\
gpr\trip\t.64\t16\t0\n\
=PC\trip\n\
=SP\trsp\n\
=BP\trbp\n\
=R0\trax\n\
=A0\trdi\n\
=A1\trsi\n\
=A2\trdx\n\
=A3\trcx\n";
		return strdup (profile);
	}

	char *profile = r2il_get_reg_profile (ctx);
	return profile ? profile : NULL;
}

static bool sleigh_arch_decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	/* Get the analysis context from the arch session user data */
	RAnal *anal = (RAnal *)as->user;
	if (!anal) {
		return false;
	}

	/* Use our existing sleigh_op function */
	return sleigh_op (anal, op, op->addr, op->bytes, op->size, mask) >= 0;
}

static int sleigh_arch_info(RArchSession *as, ut32 query) {
	RAnal *anal = (RAnal *)as->user;
	if (!anal) {
		return 0;
	}

	R2ILContext *ctx = get_context (anal);
	if (!ctx) {
		return 0;
	}

	switch (query) {
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 15;
	case R_ARCH_INFO_CODE_ALIGN:
		return 1;
	case R_ARCH_INFO_DATA_ALIGN:
		return 1;
	case R_ARCH_INFO_FUNC_ALIGN:
		return 1;
	default:
		return 0;
	}
}

/* Define architecture plugins for different variants */
const RArchPlugin r_arch_plugin_sleigh_x86 = {
	.meta = {
		.name = "r2sleigh",
		.author = "r2sleigh project",
		.desc = "Sleigh-based architecture via r2sleigh (P-code to ESIL)",
		.license = "LGPL3",
	},
	.arch = "r2sleigh",
	.bits = R_SYS_BITS_PACK1 (32) | R_SYS_BITS_PACK1 (64),
	.decode = sleigh_arch_decode,
	.info = sleigh_arch_info,
	.regs = sleigh_arch_regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_arch_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_sleigh_x86,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
