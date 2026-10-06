#include "Belt.h"
#include <utility>
#include <stdexcept>

Belt::Belt() {
    buildSBox();
}


void Belt::buildSBox() {
    for (int x = 0; x < 256; ++x) {
        Hbox[x] = (x == 0) ? 0 : calc.gf_inv(static_cast<uint8_t>(x));
    }
}

uint8_t Belt::ctTableLookup(const std::array<uint8_t, 256>& table, uint8_t idx) {
    uint8_t result = 0;
    for (int i = 0; i < 256; ++i) {
        uint8_t diff = static_cast<uint8_t>(i) ^ idx;      // 0 <=> i == idx
        int32_t t = static_cast<int32_t>(diff) - 1;        // -1 если diff==0, иначе >= 0
        uint8_t mask = static_cast<uint8_t>(t >> 31);       // арифметический сдвиг: 0xFF если diff==0, иначе 0x00
        result |= table[i] & mask;
    }
    return result;
}

uint8_t Belt::H(uint8_t x) const { return ctTableLookup(Hbox, x); }

// ---------------------------------------------------------------------
// Циклический сдвиг 32-битного слова влево
// ---------------------------------------------------------------------
uint32_t Belt::rotl32(uint32_t x, int r) {
    r &= 31;
    return (x << r) | (x >> (32 - r));
}

// ---------------------------------------------------------------------
// G_r(u) = (H(u0) || H(u1) || H(u2) || H(u3)) <<< r
// где u0 — старший байт u, u3 — младший (big-endian порядок байт внутри слова)
// ---------------------------------------------------------------------
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

uint32_t Belt::G5(uint32_t u) const { return G(u, 5); }
uint32_t Belt::G13(uint32_t u) const { return G(u, 13); }
uint32_t Belt::G21(uint32_t u) const { return G(u, 21); }

// ---------------------------------------------------------------------
// Расширение ключа (belt-keyexpand): key (16/24/32 байта) -> 8 слов по 32 бита
// ---------------------------------------------------------------------
static uint32_t loadWordLE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
}

std::array<uint32_t, 8> Belt::keyExpand(const std::vector<uint8_t>& key) const {
    std::array<uint32_t, 8> w{};

    if (key.size() == 32) {
        for (int i = 0; i < 8; ++i) w[i] = loadWordLE(&key[4 * i]);
    }
    else if (key.size() == 16) {
        for (int i = 0; i < 4; ++i) {
            uint32_t word = loadWordLE(&key[4 * i]);
            w[i] = word;
            w[i + 4] = word;
        }
    }
    else if (key.size() == 24) {
        for (int i = 0; i < 6; ++i) w[i] = loadWordLE(&key[4 * i]);
        // Y1 = w0,w1  Y2 = w2,w3  Y3 = w4,w5 ; w6..w7 = Y1 xor Y2 xor Y3
        w[6] = w[0] ^ w[2] ^ w[4];
        w[7] = w[1] ^ w[3] ^ w[5];
    }
    else {
        throw std::invalid_argument("belt key length must be 16, 24 or 32 bytes");
    }
    return w;
}

// ---------------------------------------------------------------------
// Индекс раундового ключа: k[7i - delta - 1] (mod 8), i = 1..8
// ---------------------------------------------------------------------
uint32_t Belt::keyIdx(const std::array<uint32_t, 8>& key, int i, int delta) {
    return key[(7 * i - delta - 1) % 8];
}

std::array<uint32_t, 4> Belt::bytesToWords(const std::array<uint8_t, 16>& block) {
    std::array<uint32_t, 4> x{};
    for (int i = 0; i < 4; ++i) x[i] = loadWordLE(&block[4 * i]);
    return x;
}

std::array<uint8_t, 16> Belt::wordsToBytes(const std::array<uint32_t, 4>& words) {
    std::array<uint8_t, 16> block{};
    for (int i = 0; i < 4; ++i) {
        uint32_t w = words[i];
        block[4 * i + 0] = static_cast<uint8_t>(w & 0xFF);
        block[4 * i + 1] = static_cast<uint8_t>((w >> 8) & 0xFF);
        block[4 * i + 2] = static_cast<uint8_t>((w >> 16) & 0xFF);
        block[4 * i + 3] = static_cast<uint8_t>((w >> 24) & 0xFF);
    }
    return block;
}

// ---------------------------------------------------------------------
// Зашифрование блока (belt-block, раздел 6.1.3 стандарта)
// ---------------------------------------------------------------------
std::array<uint8_t, 16> Belt::encryptBlock(const std::array<uint8_t, 16>& block,
    const std::array<uint32_t, 8>& key) const {
    auto x = bytesToWords(block);
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

    return wordsToBytes({ b, d, a, c });
}

// ---------------------------------------------------------------------
// Расшифрование блока (обратное преобразование)
// ---------------------------------------------------------------------
std::array<uint8_t, 16> Belt::decryptBlock(const std::array<uint8_t, 16>& block,
    const std::array<uint32_t, 8>& key) const {
    auto x = bytesToWords(block);
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

    return wordsToBytes({ c, a, d, b });
}
