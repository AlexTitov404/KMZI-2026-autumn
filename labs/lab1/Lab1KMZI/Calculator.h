#pragma once
#include <cstdint>
#include <cstddef>

class Calculator {
public:
    static constexpr uint16_t MOD = 0x11B;

    uint8_t gf_add(uint8_t a, uint8_t b);
    uint8_t gf_mul(uint8_t a, uint8_t b);
    uint8_t gf_inv(uint8_t a);
};