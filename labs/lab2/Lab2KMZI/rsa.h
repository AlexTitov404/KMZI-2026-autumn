#ifndef RSA_H
#define RSA_H

#include <cstddef>
#include <cstdint>

namespace rsa_detail {

    template <std::size_t L>
    struct MontCtx {
        std::uint64_t mod[L];
        std::uint64_t rr[L];   
        std::uint64_t one[L];  
        std::uint64_t n0inv;  
    };
}  

class RSA{
public:
    static constexpr std::size_t kModulusBits = 2048;
    static constexpr std::size_t kModulusBytes = 256;
    static constexpr std::size_t kPrimeBytes = 128;  
    static constexpr std::size_t kHashBytes = 64;   
    static constexpr std::size_t kMaxMessageBytes = kModulusBytes - 2 * kHashBytes - 2;
    static constexpr std::uint32_t kPublicExponent = 65537;

    enum class Status {
        Ok = 0,
        InvalidArgument,  
        InvalidKey,      
        OutOfRange,      
        MessageTooLong,  
        DecryptionError, 
        RngFailure,      
        FaultDetected,    
        BadSignature      
    };

    using RandomFn = bool (*)(void* ctx, void* buf, std::size_t len);

    RSA();
    ~RSA();  
    RSA(const RSA&) = delete;  
    RSA& operator=(const RSA&) = delete;

    Status generateKeys(RandomFn rng = nullptr, void* rngCtx = nullptr);
    Status loadPrivateKey(const std::uint8_t* p, const std::uint8_t* q);
    Status loadPublicKey(const std::uint8_t* n);

    bool hasPublicKey() const { return hasPublic_; }
    bool hasPrivateKey() const { return hasPrivate_; }
    Status getModulus(std::uint8_t* n ) const;
    Status exportPrivateKey(std::uint8_t* p , std::uint8_t* q ) const;
    Status encrypt(const std::uint8_t* msg, std::size_t msgLen,
        const std::uint8_t* label, std::size_t labelLen,
        std::uint8_t* cipher, RandomFn rng = nullptr, void* rngCtx = nullptr) const;
    Status decrypt(const std::uint8_t* cipher,
        const std::uint8_t* label, std::size_t labelLen,
        std::uint8_t* out, std::size_t outCap, std::size_t& outLen) const;

    Status rawPublic(const std::uint8_t* in, std::uint8_t* out) const;   
    Status rawPrivate(const std::uint8_t* in, std::uint8_t* out) const;  
    Status sign(const std::uint8_t* digest, std::uint8_t* signature) const;
    Status verify(const std::uint8_t* signature, const std::uint8_t* digest) const;

    static bool systemRandom(void* ctx, void* buf, std::size_t len);

private:
    Status setPrivate(const std::uint64_t* p, const std::uint64_t* q);
    void wipe();

    rsa_detail::MontCtx<32> mn_;                 
    rsa_detail::MontCtx<16> mp_, mq_;            
    std::uint64_t dp_[16], dq_[16];             
    std::uint64_t qinv_[16];                    
    bool hasPublic_, hasPrivate_;
};

#endif 

