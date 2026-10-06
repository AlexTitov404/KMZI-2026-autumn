#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include "Belt.h"

class BeltGcm {
public:
    explicit BeltGcm(const std::array<uint32_t, 8>& expandedKey);

    struct Encrypted {
        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, 16> tag{};
    };

    Encrypted encrypt(const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad) const;

    bool decrypt(const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const std::array<uint8_t, 16>& tag,
        std::vector<uint8_t>& plaintextOut) const;

    static std::array<uint8_t, 16> gf128Mul(const std::array<uint8_t, 16>& X,
        const std::array<uint8_t, 16>& Y);

    std::array<uint8_t, 16> ghash(const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& c) const;

    const std::array<uint8_t, 16>& hashSubkey() const { return Hsub; }
    void setHashSubkeyForTesting(const std::array<uint8_t, 16>& h) { Hsub = h; }

private:
    Belt belt;
    std::array<uint32_t, 8> key;
    std::array<uint8_t, 16> Hsub{};

    std::array<uint8_t, 16> computeJ0(const std::vector<uint8_t>& iv) const;

    static void incr32(std::array<uint8_t, 16>& block);

    std::vector<uint8_t> ctr(std::array<uint8_t, 16> icb, const std::vector<uint8_t>& input) const;

    static bool ctEqual(const std::array<uint8_t, 16>& a, const std::array<uint8_t, 16>& b);
};

