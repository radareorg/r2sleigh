// Simple test function for end-to-end testing
int add(int a, int b) {
    return a + b;
}

int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

int sum_array(int *arr, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

int main() {
    int result = add(5, 3);
    result = factorial(5);
    int arr[] = {1, 2, 3, 4, 5};
    result = sum_array(arr, 5);
    return result;
}
