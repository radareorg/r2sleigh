// Test program for symbolic execution analysis
// Compile with: gcc -O0 -g -o sym_test sym_test.c

#include <stdio.h>
#include <stdlib.h>

// Simple function with conditional branch
// Symbolic execution should find both paths
int check_password(int input) {
    if (input == 0x1337) {
        return 1;  // Success path
    }
    return 0;  // Failure path
}

// Function with multiple conditions
// Tests path exploration with constraints
int grade_score(int score) {
    if (score >= 90) {
        return 4;  // A
    } else if (score >= 80) {
        return 3;  // B
    } else if (score >= 70) {
        return 2;  // C
    } else if (score >= 60) {
        return 1;  // D
    }
    return 0;  // F
}

// Function with arithmetic operations
// Tests symbolic arithmetic
int compute(int x, int y) {
    int a = x + y;
    int b = x - y;
    int c = a * b;
    return c;
}

// Function with bitwise operations
// Tests symbolic bitwise handling
int bitops(unsigned int x) {
    unsigned int a = x & 0xFF;
    unsigned int b = x >> 4;
    unsigned int c = a | b;
    return c;
}

// Simple loop (bounded)
// Tests loop unrolling in symbolic execution
int sum_to_n(int n) {
    int sum = 0;
    for (int i = 1; i <= n && i <= 10; i++) {
        sum += i;
    }
    return sum;
}

// Memory access pattern
// Tests symbolic memory model
int array_access(int *arr, int idx) {
    if (idx >= 0 && idx < 5) {
        return arr[idx];
    }
    return -1;
}

int main(int argc, char *argv[]) {
    int input = 0;
    if (argc > 1) {
        input = atoi(argv[1]);
    }
    
    printf("check_password(%d) = %d\n", input, check_password(input));
    printf("grade_score(%d) = %d\n", input, grade_score(input));
    printf("compute(%d, 10) = %d\n", input, compute(input, 10));
    printf("bitops(%d) = %d\n", input, bitops(input));
    printf("sum_to_n(%d) = %d\n", input, sum_to_n(input));
    
    int arr[] = {10, 20, 30, 40, 50};
    printf("array_access(arr, %d) = %d\n", input, array_access(arr, input));
    
    return 0;
}
