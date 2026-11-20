// D570: GCC moves the unlikely throw and its cleanups into `build.cold`.
#include <stdexcept>
#include <string>
#include <vector>

__attribute__((noinline)) unsigned long build(int n) {
    std::vector<std::string> names;
    for (int i = 0; i < n; ++i)
        names.push_back(std::to_string(i));
    if (__builtin_expect(names.size() > 1000, 0))
        throw std::length_error("too many");
    return names.size();
}

int main(int argc, char **) { return static_cast<int>(build(argc)); }
