
#include <cstdint>
#include <iostream>

int main() {
    uint8_t msgType = 64;

    int intTest = static_cast<int>(msgType);
    std::cout << "Integer " << intTest << std::endl;

    uint8_t uintTest = static_cast<uint8_t>(intTest);
    std::cout << "uint8_t " << uintTest << std::endl;
    return 0;
}