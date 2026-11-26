// AArch64 GOT reads of a symbol plus an addend, each through the slot GDAT(S+A).
//   clang -target aarch64-linux-gnu -c aarch64_got_addend.s -o aarch64_got_addend.elf
	.text
	.globl	f
f:
	adrp	x0, :got:gdef+8
	ldr	x0, [x0, :got_lo12:gdef+8]
	adrp	x1, :got:gdef
	ldr	x1, [x1, :got_lo12:gdef]
	adrp	x2, :got:gundef+8
	ldr	x2, [x2, :got_lo12:gundef+8]
	ret
	.data
	.globl	gdef
gdef:
	.quad	1, 2
