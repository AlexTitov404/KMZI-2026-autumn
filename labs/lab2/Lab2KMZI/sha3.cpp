#include "sha3.h"

namespace {

    using u64 = std::uint64_t;
    using u8 = std::uint8_t;

    void secureZero(void* p, std::size_t len) {
        volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
        while (len--) *v++ = 0;
    }

    inline u64 rotl(u64 x, unsigned n) { return (x << n) | (x >> (64 - n)); }  

    void keccakF(u64 st[25]) {
        static const u64 kRoundConst[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL };
        static const unsigned kRot[24] = { 1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                          27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44 };
        static const unsigned kPi[24] = { 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                         15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 };

        for (unsigned round = 0; round < 24; ++round) {
            u64 bc[5];
            for (unsigned i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            for (unsigned i = 0; i < 5; ++i) {
                const u64 t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1);
                for (unsigned j = 0; j < 25; j += 5) st[j + i] ^= t;
            }
            u64 t = st[1];
            for (unsigned i = 0; i < 24; ++i) {
                const unsigned j = kPi[i];
                const u64 tmp = st[j];
                st[j] = rotl(t, kRot[i]);
                t = tmp;
            }
            for (unsigned j = 0; j < 25; j += 5) {
                for (unsigned i = 0; i < 5; ++i) bc[i] = st[j + i];
                for (unsigned i = 0; i < 5; ++i) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
            st[0] ^= kRoundConst[round];
        }
    }

}

Sha3_512::~Sha3_512() {
    secureZero(state_, sizeof state_);
    secureZero(buf_, sizeof buf_);
    pos_ = 0;
}

void Sha3_512::reset() {
    for (std::size_t i = 0; i < 25; ++i) state_[i] = 0;
    for (std::size_t i = 0; i < kRateBytes; ++i) buf_[i] = 0;
    pos_ = 0;
}

void Sha3_512::absorbBlock() {
    for (std::size_t i = 0; i < kRateBytes / 8; ++i) {
        u64 lane = 0;
        for (std::size_t j = 0; j < 8; ++j) lane |= static_cast<u64>(buf_[8 * i + j]) << (8 * j);
        state_[i] ^= lane;
    }
    keccakF(state_);
}

void Sha3_512::update(const u8* data, std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        buf_[pos_++] = data[i];
        if (pos_ == kRateBytes) {
            absorbBlock();
            pos_ = 0;
        }
    }
}

void Sha3_512::finish(u8 out[kDigestBytes]) {
    for (std::size_t i = pos_; i < kRateBytes; ++i) buf_[i] = 0;
    buf_[pos_] ^= 0x06;              
    buf_[kRateBytes - 1] ^= 0x80;    
    absorbBlock();
    for (std::size_t i = 0; i < kDigestBytes; ++i) {
        out[i] = static_cast<u8>(state_[i / 8] >> (8 * (i % 8)));
    }
    secureZero(state_, sizeof state_);
    secureZero(buf_, sizeof buf_);
    pos_ = 0;
}

void Sha3_512::hash(const u8* data, std::size_t len, u8 out[kDigestBytes]) {
    Sha3_512 h;
    h.update(data, len);
    h.finish(out);
}
