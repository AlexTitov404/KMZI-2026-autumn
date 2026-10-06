#include "Calculator.h"
#include <stdexcept>

uint8_t Calculator::gf_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

uint8_t Calculator::gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

uint8_t Calculator::gf_inv(uint8_t a) {
    if (a == 0) throw std::runtime_error("0 has no inverse");
    uint8_t result = 1, base = a;
    int exp = 254;
    while (exp > 0) {
        if (exp & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}