#include <iostream>

namespace compat {

int add(int left, int right) {
    int total = left + right;
    return total;
}

}  // namespace compat

int main() {
    int value = compat::add(20, 22);
    std::cout << "value=" << value << '\n';
    return value == 42 ? 0 : 1;
}
