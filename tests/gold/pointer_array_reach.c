/* A frame array whose only indexed reads happen inside a callee. */
#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) uint64_t table_load(uint64_t **base, unsigned index) {
	return *base[index];
}

__attribute__((noinline)) void table_store(uint64_t **base, unsigned index, uint64_t value) {
	*base[index] = value;
}

__attribute__((noinline)) uint64_t pointer_array_reach(uint64_t a, uint64_t b) {
	uint64_t zero = a;
	uint64_t one = b;
	uint64_t two = a ^ b;
	uint64_t three = a + b;
	uint64_t *rows[4] = {&zero, &one, &two, &three};

	uint64_t accumulator = 0;
	for (unsigned index = 0; index < 4u; index++) {
		accumulator = accumulator * 1000003u + table_load(rows, index);
	}
	table_store(rows, 1u, accumulator);
	return accumulator ^ zero;
}

int main(void) {
	printf("%016llx\n", (unsigned long long)pointer_array_reach(0x1234, 0x5678));
	return 0;
}
