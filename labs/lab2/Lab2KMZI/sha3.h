#ifndef SHA3_H
#define SHA3_H

#include <cstddef>
#include <cstdint>

class Sha3_512 {
public:
    static constexpr std::size_t kDigestBytes = 64;
    static constexpr std::size_t kRateBytes = 72;  

    Sha3_512() { reset(); }
    ~Sha3_512();
    Sha3_512(const Sha3_512&) = delete;
    Sha3_512& operator=(const Sha3_512&) = delete;

    void reset();
    void update(const std::uint8_t* data, std::size_t len);
    void finish(std::uint8_t out[kDigestBytes]);  
    static void hash(const std::uint8_t* data, std::size_t len, std::uint8_t out[kDigestBytes]);

private:
    void absorbBlock();

    std::uint64_t state_[25];
    std::uint8_t buf_[kRateBytes];
    std::size_t pos_;
};

#endif  

