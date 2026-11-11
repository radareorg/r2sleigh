#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
__attribute__((noinline)) uint32_t used_sum(const uint8_t *p, size_t n) { uint32_t s = 0; while (n--) s += *p++; return s; }
__attribute__((noinline)) uint32_t never_called(const uint8_t *p, size_t n) { uint32_t s = 1; while (n--) s = s * 31 + *p++; return s; }
int main(int argc, char **argv) { printf("%u\n", used_sum((const uint8_t *)argv[0], 4)); return argc; }
