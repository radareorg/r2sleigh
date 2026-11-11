/* Apple clang 21 `-arch arm64 -O1 macho_two_level.c -lz -Wl,-dead_strip`: a two-level namespace
 * image whose `_puts` names libSystem by library ordinal 2 and `_zlibVersion` libz by ordinal 1. */
#include <stdio.h>
#include <zlib.h>
int main(void) { puts(zlibVersion()); return 0; }
