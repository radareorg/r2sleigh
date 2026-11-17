// D570: a call inside a try with a destructor to run, and a handler that returns to the caller.
#include <cstdio>
#include <stdexcept>

struct Guard {
    int *count;
    ~Guard();
};

Guard::~Guard() {
    if (count)
        ++*count;
}

__attribute__((noinline)) int risky(int x) {
    if (x > 3)
        throw std::runtime_error("big");
    return x * 2;
}

__attribute__((noinline)) int guarded(int x) {
    int count = 0;
    try {
        Guard guard{&count};
        return risky(x) + count;
    } catch (const std::exception &error) {
        std::puts(error.what());
        return -1;
    }
}

int main(int argc, char **) { return guarded(argc); }
