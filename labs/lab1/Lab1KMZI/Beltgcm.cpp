#include "BeltGcm.h"
#include <cstring>

BeltGcm::BeltGcm(const uint32_t expandedKey[8]) {
    for (int i = 0; i < 8; ++i) key[i] = expandedKey[i];
    uint8_t zero[16] = { 0 };
    belt.encryptBlock(zero, key, Hsub);
}

void BeltGcm::gf128Mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]) {
    uint8_t V[16];
    std::memcpy(V, Y, 16);
    std::memset(Z, 0, 16);

    constexpr uint8_t R0 = 0xE1;

    for (int i = 0; i < 128; ++i) {
        int byteIdx = i / 8;
        int bitIdx = 7 - (i % 8);
        uint8_t xbit = (X[byteIdx] >> bitIdx) & 1;
        uint8_t mask = static_cast<uint8_t>(0 - xbit);

        for (int k = 0; k < 16; ++k) Z[k] ^= (V[k] & mask);

        uint8_t lsb = V[15] & 1;
        uint8_t lmask = static_cast<uint8_t>(0 - lsb);

        uint8_t carry = 0;
        for (int k = 0; k < 16; ++k) {
            uint8_t newCarry = V[k] & 1;
            V[k] = static_cast<uint8_t>((V[k] >> 1) | (carry << 7));
            carry = newCarry;
        }
        V[0] ^= (R0 & lmask);
    }
}

static void ghashBlock(uint8_t y[16], const uint8_t* block, const uint8_t H[16]) {
    uint8_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = y[i] ^ block[i];
    BeltGcm::gf128Mul(x, H, y);
}

void BeltGcm::ghash(const uint8_t* aad, size_t aadLen,
    const uint8_t* c, size_t cLen,
    uint8_t out[16]) const {
    uint8_t y[16] = { 0 };

    size_t i = 0;
    for (; i + 16 <= aadLen; i += 16) ghashBlock(y, &aad[i], Hsub);
    if (i < aadLen) {
        uint8_t block[16] = { 0 };
        std::memcpy(block, &aad[i], aadLen - i);
        ghashBlock(y, block, Hsub);
    }

    i = 0;
    for (; i + 16 <= cLen; i += 16) ghashBlock(y, &c[i], Hsub);
    if (i < cLen) {
        uint8_t block[16] = { 0 };
        std::memcpy(block, &c[i], cLen - i);
        ghashBlock(y, block, Hsub);
    }

    uint8_t lenBlock[16] = { 0 };
    uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
    uint64_t cBits = static_cast<uint64_t>(cLen) * 8;
    for (int k = 0; k < 8; ++k) lenBlock[k] = static_cast<uint8_t>(aadBits >> (56 - 8 * k));
    for (int k = 0; k < 8; ++k) lenBlock[8 + k] = static_cast<uint8_t>(cBits >> (56 - 8 * k));
    ghashBlock(y, lenBlock, Hsub);

    std::memcpy(out, y, 16);
}

void BeltGcm::computeJ0(const uint8_t* iv, size_t ivLen, uint8_t J0[16]) const {
    std::memset(J0, 0, 16);
    if (ivLen == 12) {
        std::memcpy(J0, iv, 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    }
    else {
        ghash(nullptr, 0, iv, ivLen, J0);
    }
}

void BeltGcm::incr32(uint8_t block[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++block[i] != 0) break;
    }
}

void BeltGcm::ctr(const uint8_t icb[16], const uint8_t* input, size_t len,
    uint8_t* out) const {
    uint8_t cb[16];
    std::memcpy(cb, icb, 16);

    size_t i = 0;
    while (i < len) {
        uint8_t ks[16];
        belt.encryptBlock(cb, key, ks);
        size_t chunk = (len - i < 16) ? (len - i) : 16;
        for (size_t k = 0; k < chunk; ++k) out[i + k] = input[i + k] ^ ks[k];
        i += chunk;
        incr32(cb);
    }
}

bool BeltGcm::ctEqual(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

void BeltGcm::encrypt(const uint8_t* iv, size_t ivLen,
    const uint8_t* plaintext, size_t ptLen,
    const uint8_t* aad, size_t aadLen,
    Encrypted& out) const {
    uint8_t J0[16];
    computeJ0(iv, ivLen, J0);

    uint8_t J0inc[16];
    std::memcpy(J0inc, J0, 16);
    incr32(J0inc);

    ctr(J0inc, plaintext, ptLen, out.ciphertext);
    out.ciphertextLen = ptLen;

    uint8_t S[16];
    ghash(aad, aadLen, out.ciphertext, ptLen, S);

    uint8_t EJ0[16];
    belt.encryptBlock(J0, key, EJ0);

    for (int i = 0; i < 16; ++i) out.tag[i] = EJ0[i] ^ S[i];
}

bool BeltGcm::decrypt(const uint8_t* iv, size_t ivLen,
    const uint8_t* ciphertext, size_t ctLen,
    const uint8_t* aad, size_t aadLen,
    const uint8_t tag[16],
    uint8_t* plaintextOut, size_t& plaintextLenOut) const {
    uint8_t J0[16];
    computeJ0(iv, ivLen, J0);

    uint8_t S[16];
    ghash(aad, aadLen, ciphertext, ctLen, S);

    uint8_t EJ0[16];
    belt.encryptBlock(J0, key, EJ0);

    uint8_t expectedTag[16];
    for (int i = 0; i < 16; ++i) expectedTag[i] = EJ0[i] ^ S[i];

    bool ok = ctEqual(expectedTag, tag);

    uint8_t J0inc[16];
    std::memcpy(J0inc, J0, 16);
    incr32(J0inc);

    ctr(J0inc, ciphertext, ctLen, plaintextOut);
    plaintextLenOut = ctLen;

    if (!ok) {
        std::memset(plaintextOut, 0, ctLen);
        plaintextLenOut = 0;
    }
    return ok;
}
