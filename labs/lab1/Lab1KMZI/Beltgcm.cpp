#include "BeltGcm.h"
#include <cstring>

BeltGcm::BeltGcm(const std::array<uint32_t, 8>& expandedKey) : key(expandedKey) {
    std::array<uint8_t, 16> zero{};
    Hsub = belt.encryptBlock(zero, key);
}

std::array<uint8_t, 16> BeltGcm::gf128Mul(const std::array<uint8_t, 16>& X,
    const std::array<uint8_t, 16>& Y) {
    std::array<uint8_t, 16> Z{};   
    std::array<uint8_t, 16> V = Y; 
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
    return Z;
}

static void ghashBlock(std::array<uint8_t, 16>& y, const uint8_t* block,
    const std::array<uint8_t, 16>& H,
    std::array<uint8_t, 16>(*mul)(const std::array<uint8_t, 16>&,
        const std::array<uint8_t, 16>&)) {
    std::array<uint8_t, 16> x{};
    for (int i = 0; i < 16; ++i) x[i] = y[i] ^ block[i];
    y = mul(x, H);
}

std::array<uint8_t, 16> BeltGcm::ghash(const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& c) const {
    std::array<uint8_t, 16> y{}; 

    size_t i = 0;
    for (; i + 16 <= aad.size(); i += 16) ghashBlock(y, &aad[i], Hsub, gf128Mul);
    if (i < aad.size()) {
        std::array<uint8_t, 16> block{};
        std::memcpy(block.data(), &aad[i], aad.size() - i);
        ghashBlock(y, block.data(), Hsub, gf128Mul);
    }

    i = 0;
    for (; i + 16 <= c.size(); i += 16) ghashBlock(y, &c[i], Hsub, gf128Mul);
    if (i < c.size()) {
        std::array<uint8_t, 16> block{};
        std::memcpy(block.data(), &c[i], c.size() - i);
        ghashBlock(y, block.data(), Hsub, gf128Mul);
    }

   
    std::array<uint8_t, 16> lenBlock{};
    uint64_t aadBits = static_cast<uint64_t>(aad.size()) * 8;
    uint64_t cBits = static_cast<uint64_t>(c.size()) * 8;
    for (int k = 0; k < 8; ++k) lenBlock[k] = static_cast<uint8_t>(aadBits >> (56 - 8 * k));
    for (int k = 0; k < 8; ++k) lenBlock[8 + k] = static_cast<uint8_t>(cBits >> (56 - 8 * k));
    ghashBlock(y, lenBlock.data(), Hsub, gf128Mul);

    return y;
}


std::array<uint8_t, 16> BeltGcm::computeJ0(const std::vector<uint8_t>& iv) const {
    std::array<uint8_t, 16> J0{};
    if (iv.size() == 12) {
        std::memcpy(J0.data(), iv.data(), 12);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    }
    else {
        
        J0 = ghash({}, iv);
    }
    return J0;
}

void BeltGcm::incr32(std::array<uint8_t, 16>& block) {
    for (int i = 15; i >= 12; --i) {
        if (++block[i] != 0) break; 
    }
}

std::vector<uint8_t> BeltGcm::ctr(std::array<uint8_t, 16> icb, const std::vector<uint8_t>& input) const {
    std::vector<uint8_t> out(input.size());
    std::array<uint8_t, 16> cb = icb;

    size_t i = 0;
    while (i < input.size()) {
        auto ks = belt.encryptBlock(cb, key); 
        size_t chunk = std::min<size_t>(16, input.size() - i);
        for (size_t k = 0; k < chunk; ++k) out[i + k] = input[i + k] ^ ks[k];
        i += chunk;
        incr32(cb);
    }
    return out;
}

bool BeltGcm::ctEqual(const std::array<uint8_t, 16>& a, const std::array<uint8_t, 16>& b) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}


BeltGcm::Encrypted BeltGcm::encrypt(const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad) const {
    auto J0 = computeJ0(iv);

    auto J0inc = J0;
    incr32(J0inc);
    auto C = ctr(J0inc, plaintext); 

    auto S = ghash(aad, C);
    auto E_J0 = belt.encryptBlock(J0, key);

    Encrypted result;
    result.ciphertext = std::move(C);
    for (int i = 0; i < 16; ++i) result.tag[i] = E_J0[i] ^ S[i];
    return result;
}


bool BeltGcm::decrypt(const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& aad,
    const std::array<uint8_t, 16>& tag,
    std::vector<uint8_t>& plaintextOut) const {
    auto J0 = computeJ0(iv);

    auto S = ghash(aad, ciphertext);
    auto E_J0 = belt.encryptBlock(J0, key);

    std::array<uint8_t, 16> expectedTag{};
    for (int i = 0; i < 16; ++i) expectedTag[i] = E_J0[i] ^ S[i];

    bool ok = ctEqual(expectedTag, tag); 

    auto J0inc = J0;
    incr32(J0inc);
    auto P = ctr(J0inc, ciphertext);

    if (ok) {
        plaintextOut = std::move(P);
        return true;
    }
    plaintextOut.clear();
    return false;
}
