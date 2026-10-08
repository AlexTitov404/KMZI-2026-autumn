#pragma once
#include <cstdint>
#include <cstddef>
#include "Belt.h"

constexpr size_t GCM_BLOCK = 16;
constexpr size_t GCM_IV_MAX = 16;
constexpr size_t GCM_MAX_DATA = 4096;

class BeltGcm {
public:
    explicit BeltGcm(const uint32_t expandedKey[8]);

    struct Encrypted {
        uint8_t ciphertext[GCM_MAX_DATA];
        size_t  ciphertextLen;
        uint8_t tag[GCM_BLOCK];
    };

    void encrypt(const uint8_t* iv, size_t ivLen,
        const uint8_t* plaintext, size_t ptLen,
        const uint8_t* aad, size_t aadLen,
        Encrypted& out) const;

    bool decrypt(const uint8_t* iv, size_t ivLen,
        const uint8_t* ciphertext, size_t ctLen,
        const uint8_t* aad, size_t aadLen,
        const uint8_t tag[GCM_BLOCK],
        uint8_t* plaintextOut, size_t& plaintextLenOut) const;

    static void gf128Mul(const uint8_t X[16], const uint8_t Y[16],
        uint8_t Z[16]);

    void ghash(const uint8_t* aad, size_t aadLen,
        const uint8_t* c, size_t cLen,
        uint8_t out[16]) const;

    const uint8_t* hashSubkey() const { return Hsub; }

private:
    Belt belt;
    uint32_t key[8];
    uint8_t  Hsub[16];

    void computeJ0(const uint8_t* iv, size_t ivLen, uint8_t J0[16]) const;

    static void incr32(uint8_t block[16]);

    void ctr(const uint8_t icb[16],
        const uint8_t* input, size_t len,
        uint8_t* out) const;

    static bool ctEqual(const uint8_t a[16], const uint8_t b[16]);
};

