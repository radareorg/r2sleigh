/* Apple clang 21 `-target x86_64-unknown-linux-gnu -g -O1 -fdebug-prefix-map=$PWD=. -c`,
 * linked with rust-lld `-flavor gnu -e _start`. clang states `ms_abi` as DW_CC_LLVM_Win64 (0xc1). */
__attribute__((ms_abi, noinline)) long diff(long a, long b) { return a - b; }
__attribute__((noinline)) long twice(long a, long b) { return diff(a, b) * 2; }
void _start(void) {}
