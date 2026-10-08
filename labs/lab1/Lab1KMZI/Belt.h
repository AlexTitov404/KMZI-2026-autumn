#pragma once
#include <cstdint>
#include <array>
#pragma once
#include <cstdint>
#include <cstddef>
#include "Calculator.h"

constexpr size_t BELT_KEY_MAX = 32;
constexpr size_t BELT_BLOCK = 16;

class Belt {
public:
    Belt();

    void buildSBox();
    uint8_t H(uint8_t x) const;

    void keyExpand(const uint8_t* key, size_t keyLen,
        uint32_t out[8]) const;

    void encryptBlock(const uint8_t in[16], const uint32_t key[8],
        uint8_t out[16]) const;

    void decryptBlock(const uint8_t in[16], const uint32_t key[8],
        uint8_t out[16]) const;

private:
    Calculator calc;
    uint8_t Hbox[256];

    static uint8_t ctTableLookup(const uint8_t table[256], uint8_t idx);

    static uint32_t rotl32(uint32_t x, int r);
    uint32_t G(uint32_t u, int r) const;
    uint32_t G5(uint32_t u) const;
    uint32_t G13(uint32_t u) const;
    uint32_t G21(uint32_t u) const;

    static uint32_t keyIdx(const uint32_t key[8], int i, int delta);
    static void bytesToWords(const uint8_t block[16], uint32_t x[4]);
    static void wordsToBytes(const uint32_t x[4], uint8_t block[16]);
};


