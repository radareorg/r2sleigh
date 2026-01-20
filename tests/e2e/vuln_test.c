// Vulnerability test cases for r2sleigh integration tests
// Compile with: gcc -O0 -g -fno-stack-protector -no-pie -o vuln_test vuln_test.c
//
// This binary is used by tests/e2e/integration_tests.rs to test all plugin features.
// When adding a new feature that needs a specific binary pattern:
// 1. Add a test function here that exercises the feature
// 2. Add it to the main() switch statement
// 3. Add an integration test in tests/e2e/integration_tests.rs
//
// Current test functions:
// - check_secret: Simple condition (symbolic execution, path exploration)
// - unlock: Multi-condition path explosion
// - vuln_memcpy: Buffer overflow (taint analysis)
// - solve_equation: Arithmetic constraint solving
// - bitwise_check: Bitwise operations
// - (others available for future test cases)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test 1: Simple password check (symbolic should find 0xDEAD)
int check_secret(int x) {
    if (x == 0xDEAD) {
        return 1;  // win
    }
    return 0;
}

// Test 2: Multi-condition unlock (tests path explosion)
int unlock(int a, int b, int c) {
    if (a == 10) {
        if (b == 20) {
            if (c == 30) {
                return 1;  // unlocked
            }
        }
    }
    return 0;
}

// Test 3: Buffer overflow (taint should track user input to memcpy size)
void vuln_memcpy(char *user_input, int user_len) {
    char buf[64];
    // VULN: user-controlled length in memcpy
    memcpy(buf, user_input, user_len);
    printf("Copied: %s\n", buf);
}

// Test 4: Format string (taint should track user input to printf)
void vuln_printf(char *user_input) {
    // VULN: user input directly in format string
    printf(user_input);
}

// Test 5: strlen on user input (tests sim layer)
int process_string(char *s) {
    size_t len = strlen(s);
    if (len > 100) {
        return -1;  // too long
    }
    if (len < 5) {
        return -2;  // too short
    }
    return (int)len;
}

// Test 6: strcmp for authentication (tests sim layer)
int authenticate(char *password) {
    if (strcmp(password, "secret123") == 0) {
        return 1;  // auth success
    }
    return 0;  // auth failed
}

// Test 7: malloc + use (tests sim layer)
char* alloc_and_copy(char *src, size_t len) {
    char *buf = malloc(len + 1);
    if (!buf) {
        return NULL;
    }
    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

// Test 8: Integer overflow before allocation
void* vuln_alloc(int count, int size) {
    // VULN: integer overflow in multiplication
    int total = count * size;
    return malloc(total);
}

// Test 9: Simple arithmetic for constraint solving
int solve_equation(int x) {
    // x * 2 + 5 == 25 => x == 10
    int result = x * 2 + 5;
    if (result == 25) {
        return 1;
    }
    return 0;
}

// Test 10: Nested conditions with arithmetic
int complex_check(int a, int b) {
    int sum = a + b;
    int diff = a - b;
    
    if (sum == 100) {
        if (diff == 20) {
            // a + b = 100, a - b = 20 => a = 60, b = 40
            return 1;
        }
    }
    return 0;
}

// Test 11: Bitwise operations
int bitwise_check(unsigned int x) {
    if ((x & 0xF0) == 0x50) {
        if ((x & 0x0F) == 0x0A) {
            // x == 0x5A
            return 1;
        }
    }
    return 0;
}

// Test 12: Array bounds check
int safe_array_access(int *arr, int idx, int len) {
    if (idx >= 0 && idx < len) {
        return arr[idx];
    }
    return -1;
}

// Test 13: CPUID instruction (tests CallOther/userop naming)
__attribute__((naked)) void test_cpuid(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile(
        "xor %eax, %eax\n\t"
        "cpuid\n\t"
        "ret\n\t"
    );
#else
    __asm__ volatile("ret");
#endif
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <test_num> [args...]\n", argv[0]);
        return 1;
    }
    
    int test = atoi(argv[1]);
    
    switch (test) {
        case 1:
            if (argc > 2) {
                int x = atoi(argv[2]);
                printf("check_secret(%d) = %d\n", x, check_secret(x));
            }
            break;
        case 2:
            if (argc > 4) {
                int a = atoi(argv[2]);
                int b = atoi(argv[3]);
                int c = atoi(argv[4]);
                printf("unlock(%d, %d, %d) = %d\n", a, b, c, unlock(a, b, c));
            }
            break;
        case 3:
            if (argc > 3) {
                int len = atoi(argv[3]);
                vuln_memcpy(argv[2], len);
            }
            break;
        case 4:
            if (argc > 2) {
                vuln_printf(argv[2]);
            }
            break;
        case 5:
            if (argc > 2) {
                printf("process_string = %d\n", process_string(argv[2]));
            }
            break;
        case 6:
            if (argc > 2) {
                printf("authenticate = %d\n", authenticate(argv[2]));
            }
            break;
        case 7:
            if (argc > 3) {
                size_t len = atoi(argv[3]);
                char *copy = alloc_and_copy(argv[2], len);
                if (copy) {
                    printf("Copied: %s\n", copy);
                    free(copy);
                }
            }
            break;
        case 8:
            if (argc > 3) {
                int count = atoi(argv[2]);
                int size = atoi(argv[3]);
                void *p = vuln_alloc(count, size);
                printf("vuln_alloc(%d, %d) = %p\n", count, size, p);
                free(p);
            }
            break;
        case 9:
            if (argc > 2) {
                int x = atoi(argv[2]);
                printf("solve_equation(%d) = %d\n", x, solve_equation(x));
            }
            break;
        case 10:
            if (argc > 3) {
                int a = atoi(argv[2]);
                int b = atoi(argv[3]);
                printf("complex_check(%d, %d) = %d\n", a, b, complex_check(a, b));
            }
            break;
        case 11:
            if (argc > 2) {
                unsigned int x = strtoul(argv[2], NULL, 0);
                printf("bitwise_check(0x%x) = %d\n", x, bitwise_check(x));
            }
            break;
        case 12: {
            int arr[] = {10, 20, 30, 40, 50};
            if (argc > 2) {
                int idx = atoi(argv[2]);
                printf("safe_array_access(arr, %d, 5) = %d\n", idx, safe_array_access(arr, idx, 5));
            }
            break;
        }
        case 13:
            test_cpuid();
            printf("test_cpuid() = ok\n");
            break;
        default:
            printf("Unknown test: %d\n", test);
            return 1;
    }
    
    return 0;
}
