#include "Belt.h"
#include <cstring>
#include <stdexcept>

Belt::Belt() {
    buildSBox();
}

void Belt::buildSBox() {
    for (int x = 0; x < 256; ++x) {
        Hbox[x] = (x == 0) ? 0 : calc.gf_inv(static_cast<uint8_t>(x));
    }
}

uint8_t Belt::ctTableLookup(const uint8_t table[256], uint8_t idx) {
    uint8_t result = 0;
    for (int i = 0; i < 256; ++i) {
        uint8_t diff = static_cast<uint8_t>(i) ^ idx;
        int32_t t = static_cast<int32_t>(diff) - 1;
        uint8_t mask = static_cast<uint8_t>(t >> 31);
        result |= table[i] & mask;
    }
    return result;
}

uint8_t Belt::H(uint8_t x) const { return ctTableLookup(Hbox, x); }

uint32_t Belt::rotl32(uint32_t x, int r) {
    r &= 31;
    return (x << r) | (x >> (32 - r));
}

uint32_t Belt::G(uint32_t u, int r) const {
    uint8_t b3 = static_cast<uint8_t>((u >> 24) & 0xFF);
    uint8_t b2 = static_cast<uint8_t>((u >> 16) & 0xFF);
    uint8_t b1 = static_cast<uint8_t>((u >> 8) & 0xFF);
    uint8_t b0 = static_cast<uint8_t>(u & 0xFF);

    uint32_t v = (static_cast<uint32_t>(H(b3)) << 24) |
        (static_cast<uint32_t>(H(b2)) << 16) |
        (static_cast<uint32_t>(H(b1)) << 8) |
        static_cast<uint32_t>(H(b0));
    return rotl32(v, r);
}

uint32_t Belt::G5(uint32_t u)  const { return G(u, 5); }
uint32_t Belt::G13(uint32_t u) const { return G(u, 13); }
uint32_t Belt::G21(uint32_t u) const { return G(u, 21); }

static uint32_t loadWordLE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
}

static void storeWordLE(uint8_t* p, uint32_t w) {
    p[0] = static_cast<uint8_t>(w & 0xFF);
    p[1] = static_cast<uint8_t>((w >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((w >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((w >> 24) & 0xFF);
}

void Belt::keyExpand(const uint8_t* key, size_t keyLen, uint32_t out[8]) const {
    for (int i = 0; i < 8; ++i) out[i] = 0;

    if (keyLen == 32) {
        for (int i = 0; i < 8; ++i) out[i] = loadWordLE(&key[4 * i]);
    }
    else if (keyLen == 16) {
        for (int i = 0; i < 4; ++i) {
            uint32_t word = loadWordLE(&key[4 * i]);
            out[i] = word;
            out[i + 4] = word;
        }
    }
    else if (keyLen == 24) {
        for (int i = 0; i < 6; ++i) out[i] = loadWordLE(&key[4 * i]);
        out[6] = out[0] ^ out[2] ^ out[4];
        out[7] = out[1] ^ out[3] ^ out[5];
    }
    else {
        throw std::invalid_argument("belt key length must be 16, 24 or 32 bytes");
    }
}

uint32_t Belt::keyIdx(const uint32_t key[8], int i, int delta) {
    return key[(7 * i - delta - 1) % 8];
}

void Belt::bytesToWords(const uint8_t block[16], uint32_t x[4]) {
    for (int i = 0; i < 4; ++i) x[i] = loadWordLE(&block[4 * i]);
}

void Belt::wordsToBytes(const uint32_t x[4], uint8_t block[16]) {
    for (int i = 0; i < 4; ++i) storeWordLE(&block[4 * i], x[i]);
}

void Belt::encryptBlock(const uint8_t in[16], const uint32_t key[8],
    uint8_t out[16]) const {
    uint32_t x[4];
    bytesToWords(in, x);
    uint32_t a = x[0], b = x[1], c = x[2], d = x[3];

    for (int i = 1; i <= 8; ++i) {
        b ^= G5(a + keyIdx(key, i, 6));
        c ^= G21(d + keyIdx(key, i, 5));
        a -= G13(b + keyIdx(key, i, 4));
        uint32_t e = G21(b + c + keyIdx(key, i, 3)) ^ static_cast<uint32_t>(i);
        b += e;
        c -= e;
        d += G13(c + keyIdx(key, i, 2));
        b ^= G21(a + keyIdx(key, i, 1));
        c ^= G5(d + keyIdx(key, i, 0));
        std::swap(a, b);
        std::swap(c, d);
        std::swap(b, c);
    }

    uint32_t res[4] = { b, d, a, c };
    wordsToBytes(res, out);
}

void Belt::decryptBlock(const uint8_t in[16], const uint32_t key[8],
    uint8_t out[16]) const {
    uint32_t x[4];
    bytesToWords(in, x);
    uint32_t a = x[0], b = x[1], c = x[2], d = x[3];

    for (int i = 8; i >= 1; --i) {
        b ^= G5(a + keyIdx(key, i, 0));
        c ^= G21(d + keyIdx(key, i, 1));
        a -= G13(b + keyIdx(key, i, 2));
        uint32_t e = G21(b + c + keyIdx(key, i, 3)) ^ static_cast<uint32_t>(i);
        b += e;
        c -= e;
        d += G13(c + keyIdx(key, i, 4));
        b ^= G21(a + keyIdx(key, i, 5));
        c ^= G5(d + keyIdx(key, i, 6));
        std::swap(a, b);
        std::swap(c, d);
        std::swap(a, d);
    }

    uint32_t res[4] = { c, a, d, b };
    wordsToBytes(res, out);
}
