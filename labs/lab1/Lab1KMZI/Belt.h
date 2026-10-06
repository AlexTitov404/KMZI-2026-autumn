#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include "Calculator.h"

class Belt {
public:
    Belt();

    void buildSBox();
    uint8_t H(uint8_t x) const;

    std::array<uint32_t, 8> keyExpand(const std::vector<uint8_t>& key) const;

    std::array<uint8_t, 16> encryptBlock(const std::array<uint8_t, 16>& block,
        const std::array<uint32_t, 8>& key) const;
    std::array<uint8_t, 16> decryptBlock(const std::array<uint8_t, 16>& block,
        const std::array<uint32_t, 8>& key) const;

private:
    Calculator calc;
    std::array<uint8_t, 256> Hbox{};
    static uint8_t ctTableLookup(const std::array<uint8_t, 256>& table, uint8_t idx);

    static uint32_t rotl32(uint32_t x, int r);
    uint32_t G(uint32_t u, int r) const;
    uint32_t G5(uint32_t u) const;
    uint32_t G13(uint32_t u) const;
    uint32_t G21(uint32_t u) const;

    static uint32_t keyIdx(const std::array<uint32_t, 8>& key, int i, int delta);
    static std::array<uint32_t, 4> bytesToWords(const std::array<uint8_t, 16>& block);
    static std::array<uint8_t, 16> wordsToBytes(const std::array<uint32_t, 4>& words);
};

