#include "rsa.h"
#include "sha3.h"


#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
extern "C" BOOLEAN NTAPI SystemFunction036(PVOID buffer, ULONG length);
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <cstdlib>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#if defined(__has_include)
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#define RSA_HAVE_GETRANDOM 1
#endif
#endif
#endif

namespace {

    using u64 = std::uint64_t;
    using u8 = std::uint8_t;
    using std::size_t;
    using rsa_detail::MontCtx;
    using Status = RSA::Status;

    constexpr u64 kE = RSA::kPublicExponent;
    constexpr size_t kHashLen = RSA::kHashBytes;
    constexpr size_t kDbLen = RSA::kModulusBytes - kHashLen - 1;  
    constexpr size_t kRestLen = kDbLen - kHashLen;                
    constexpr size_t kMaxMsg = RSA::kMaxMessageBytes;             

    inline u64 ctIsNonZero(u64 x) { return (x | (0 - x)) >> 63; }
    inline u64 ctIsZero(u64 x) { return ctIsNonZero(x) ^ 1; }
    inline u64 ctEq(u64 a, u64 b) { return ctIsZero(a ^ b); }
    inline u64 ctLt(u64 a, u64 b) { return ((~a & b) | (~(a ^ b) & (a - b))) >> 63; }
    inline u64 ctMask(u64 bit) { return 0 - bit; } 
    inline u64 ctSelect(u64 mask, u64 a, u64 b) { return (a & mask) | (b & ~mask); }
    inline u8 ctSelect8(u64 mask, u8 a, u8 b) {
        return static_cast<u8>((static_cast<u64>(a) & mask) | (static_cast<u64>(b) & ~mask));
    }

    u64 ctEqBytes(const u8* a, const u8* b, size_t len) {
        u64 acc = 0;
        for (size_t i = 0; i < len; ++i) acc |= static_cast<u64>(a[i] ^ b[i]);
        return ctIsZero(acc);
    }

    void secureZero(void* p, size_t len) {
        volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
        while (len--) *v++ = 0;
    }

    struct ZeroOnExit {
        void* p;
        size_t n;
        ZeroOnExit(void* p_, size_t n_) : p(p_), n(n_) {}
        ~ZeroOnExit() { secureZero(p, n); }
        ZeroOnExit(const ZeroOnExit&) = delete;
        ZeroOnExit& operator=(const ZeroOnExit&) = delete;
    };

    u64 ctDivRem(u64 hi, u64 lo, u64 v, u64& rem) {
        u64 r = 0, q = 0;
        for (int i = 63; i >= 0; --i) {
            r = (r << 1) | ((hi >> i) & 1);
            const u64 ge = ctLt(r, v) ^ 1;
            r -= v & ctMask(ge);
            q = (q << 1) | ge;
        }
        for (int i = 63; i >= 0; --i) {
            r = (r << 1) | ((lo >> i) & 1);
            const u64 ge = ctLt(r, v) ^ 1;
            r -= v & ctMask(ge);
            q = (q << 1) | ge;
        }
        rem = r;
        return q;
    }

#if defined(__SIZEOF_INT128__)
    __extension__ typedef unsigned __int128 u128;
    inline void mulAdd2(u64 a, u64 b, u64 c, u64 d, u64& hi, u64& lo) {
        const u128 t = static_cast<u128>(a) * b + c + d;
        lo = static_cast<u64>(t);
        hi = static_cast<u64>(t >> 64);
    }
#else
    inline void mulAdd2(u64 a, u64 b, u64 c, u64 d, u64& hi, u64& lo) {
        const u64 M = 0xFFFFFFFFULL;
        const u64 a0 = a & M, a1 = a >> 32, b0 = b & M, b1 = b >> 32;
        const u64 p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
        const u64 mid = (p00 >> 32) + (p01 & M) + (p10 & M);
        lo = (p00 & M) | (mid << 32);
        hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
        lo += c;
        hi += (lo < c);
        lo += d;
        hi += (lo < d);
    }
#endif

    template <size_t L>
    inline void copyN(u64* r, const u64* a) {
        for (size_t i = 0; i < L; ++i) r[i] = a[i];
    }

    template <size_t L>
    inline void zeroN(u64* r) {
        for (size_t i = 0; i < L; ++i) r[i] = 0;
    }

    template <size_t L>
    u64 addN(u64* r, const u64* a, const u64* b) {
        u64 carry = 0;
        for (size_t i = 0; i < L; ++i) {
            const u64 s = a[i] + b[i];
            const u64 c1 = s < a[i];
            const u64 s2 = s + carry;
            const u64 c2 = s2 < s;
            r[i] = s2;
            carry = c1 | c2;
        }
        return carry;
    }

    template <size_t L>
    u64 subN(u64* r, const u64* a, const u64* b) {
        u64 borrow = 0;
        for (size_t i = 0; i < L; ++i) {
            const u64 ai = a[i], bi = b[i];
            const u64 d = ai - bi;
            const u64 b1 = ai < bi;
            const u64 d2 = d - borrow;
            const u64 b2 = d < borrow;
            r[i] = d2;
            borrow = b1 | b2;
        }
        return borrow;
    }

    template <size_t L>
    inline void selectN(u64 mask, u64* r, const u64* a, const u64* b) {
        for (size_t i = 0; i < L; ++i) r[i] = (a[i] & mask) | (b[i] & ~mask);
    }

    template <size_t L>
    inline void swapN(u64 mask, u64* a, u64* b) {
        for (size_t i = 0; i < L; ++i) {
            const u64 t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    }

    template <size_t L>
    inline u64 eqN(const u64* a, const u64* b) {
        u64 acc = 0;
        for (size_t i = 0; i < L; ++i) acc |= a[i] ^ b[i];
        return ctIsZero(acc);
    }

    template <size_t L>
    inline u64 ltN(const u64* a, const u64* b) {
        u64 tmp[L];
        return subN<L>(tmp, a, b);
    }

    template <size_t L>
    void modDouble(u64* x, const u64* mod) {
        u64 t[L], u[L];
        const u64 carry = addN<L>(t, x, x);
        const u64 borrow = subN<L>(u, t, mod);
        selectN<L>(ctMask(carry | (borrow ^ 1)), x, u, t);
    }

    template <size_t L>
    void modSub(u64* r, const u64* a, const u64* b, const u64* mod) {
        u64 t[L];
        const u64 borrow = subN<L>(r, a, b);
        addN<L>(t, r, mod);
        selectN<L>(ctMask(borrow), r, t, r);
    }

    template <size_t L>
    void modAdd(u64* r, const u64* a, const u64* b, const u64* mod) {
        u64 t[L], u[L];
        const u64 carry = addN<L>(t, a, b);
        const u64 borrow = subN<L>(u, t, mod);
        selectN<L>(ctMask(carry | (borrow ^ 1)), r, u, t);
    }

    template <size_t L>
    void reduceOnce(u64* x, const u64* mod) {
        u64 u[L];
        const u64 borrow = subN<L>(u, x, mod);
        selectN<L>(ctMask(borrow ^ 1), x, u, x);
    }

    template <size_t L>
    void mulFull(u64* r, const u64* a, const u64* b) {
        for (size_t i = 0; i < 2 * L; ++i) r[i] = 0;
        for (size_t i = 0; i < L; ++i) {
            u64 carry = 0;
            for (size_t j = 0; j < L; ++j) {
                u64 hi, lo;
                mulAdd2(a[i], b[j], r[i + j], carry, hi, lo);
                r[i + j] = lo;
                carry = hi;
            }
            r[i + L] = carry;
        }
    }

    template <size_t L>
    void fromBytes(u64* w, const u8* b) {
        for (size_t i = 0; i < L; ++i) {
            const u8* src = b + 8 * (L - 1 - i);
            u64 v = 0;
            for (size_t j = 0; j < 8; ++j) v = (v << 8) | src[j];
            w[i] = v;
        }
    }

    template <size_t L>
    void toBytes(u8* b, const u64* w) {
        for (size_t i = 0; i < L; ++i) {
            u8* dst = b + 8 * (L - 1 - i);
            for (size_t j = 0; j < 8; ++j) dst[j] = static_cast<u8>(w[i] >> (56 - 8 * j));
        }
    }

    template <size_t L>
    void montInit(MontCtx<L>& m, const u64* mod) {
        copyN<L>(m.mod, mod);
        u64 inv = mod[0];  
        for (int i = 0; i < 5; ++i) inv *= 2 - mod[0] * inv;
        m.n0inv = 0 - inv;
        u64 x[L];
        zeroN<L>(x);
        x[0] = 1;
        for (size_t i = 0; i < 64 * L; ++i) modDouble<L>(x, mod);
        copyN<L>(m.one, x);
        for (size_t i = 0; i < 64 * L; ++i) modDouble<L>(x, mod);
        copyN<L>(m.rr, x);
    }

    template <size_t L>
    void montMul(const MontCtx<L>& m, u64* r, const u64* a, const u64* b) {
        u64 t[L + 2];
        for (size_t i = 0; i < L + 2; ++i) t[i] = 0;

        for (size_t i = 0; i < L; ++i) {
            u64 carry = 0, hi, lo;
            for (size_t j = 0; j < L; ++j) {
                mulAdd2(a[i], b[j], t[j], carry, hi, lo);
                t[j] = lo;
                carry = hi;
            }
            const u64 s = t[L] + carry;
            t[L + 1] = s < carry;
            t[L] = s;

            const u64 q = t[0] * m.n0inv;
            mulAdd2(q, m.mod[0], t[0], 0, hi, lo);
            carry = hi;
            for (size_t j = 1; j < L; ++j) {
                mulAdd2(q, m.mod[j], t[j], carry, hi, lo);
                t[j - 1] = lo;
                carry = hi;
            }
            const u64 s2 = t[L] + carry;
            const u64 c2 = s2 < carry;
            t[L - 1] = s2;
            t[L] = t[L + 1] + c2;
        }

        u64 u[L];
        const u64 borrow = subN<L>(u, t, m.mod);
        selectN<L>(ctMask(t[L] | (borrow ^ 1)), r, u, t);
        secureZero(t, sizeof t);
    }

    template <size_t L>
    inline void toMont(const MontCtx<L>& m, u64* r, const u64* a) {
        montMul<L>(m, r, a, m.rr);
    }

    template <size_t L>
    inline void fromMont(const MontCtx<L>& m, u64* r, const u64* a) {
        u64 one[L];
        zeroN<L>(one);
        one[0] = 1;
        montMul<L>(m, r, a, one);
    }

    template <size_t L>
    void montPow(const MontCtx<L>& m, u64* out, const u64* base, const u64* exp) {
        u64 r0[L], r1[L];
        copyN<L>(r0, m.one);
        copyN<L>(r1, base);
        for (size_t k = 64 * L; k-- > 0;) {
            const u64 mask = ctMask((exp[k >> 6] >> (k & 63)) & 1);
            swapN<L>(mask, r0, r1);
            montMul<L>(m, r1, r0, r1);
            montMul<L>(m, r0, r0, r0);
            swapN<L>(mask, r0, r1);
        }
        copyN<L>(out, r0);
        secureZero(r0, sizeof r0);
        secureZero(r1, sizeof r1);
    }

    void publicPow(const MontCtx<32>& m, u64* out, const u64* x) {
        u64 xm[32], r[32];
        toMont<32>(m, xm, x);
        copyN<32>(r, xm); 
        for (int i = 15; i >= 0; --i) {
            montMul<32>(m, r, r, r);
            if ((kE >> i) & 1) montMul<32>(m, r, r, xm);
        }
        fromMont<32>(m, out, r);
        secureZero(xm, sizeof xm);
        secureZero(r, sizeof r);
    }

    void reduceWide(const MontCtx<16>& m, u64* r, const u64* c) {
        u64 t0[16], t1[16];
        copyN<16>(t0, c);
        reduceOnce<16>(t0, m.mod);       
        montMul<16>(m, t1, c + 16, m.rr);  
        modAdd<16>(r, t0, t1, m.mod);
    }

    bool crtExponent(const u64* prime, u64* dOut) {
        u64 pm1[16], one[16] = { 1 };
        subN<16>(pm1, prime, one);

        u64 a = 0; 
        for (size_t i = 16; i-- > 0;) {
            u64 r;
            ctDivRem(a, pm1[i], kE, r);
            a = r;
        }
        if (a == 0) return false;

        u64 inv = 1;  
        for (int bit = 15; bit >= 0; --bit) {
            u64 r;
            ctDivRem(0, inv * inv, kE, r);
            inv = r;
            if (((kE - 2) >> bit) & 1) {
                ctDivRem(0, inv * a, kE, r);
                inv = r;
            }
        }
        const u64 k = kE - inv;

        u64 t[17]; 
        u64 carry = 0, hi, lo;
        for (size_t i = 0; i < 16; ++i) {
            mulAdd2(pm1[i], k, 0, carry, hi, lo);
            t[i] = lo;
            carry = hi;
        }
        t[16] = carry;
        u64 c1 = 1;
        for (size_t i = 0; i < 17; ++i) {
            const u64 s = t[i] + c1;
            c1 = s < c1;
            t[i] = s;
        }

        u64 rem = 0, qt[17];  
        for (size_t i = 17; i-- > 0;) {
            u64 r;
            qt[i] = ctDivRem(rem, t[i], kE, r);
            rem = r;
        }
        const bool ok = rem == 0 && qt[16] == 0;
        if (ok) copyN<16>(dOut, qt);
        secureZero(t, sizeof t);
        secureZero(qt, sizeof qt);
        secureZero(pm1, sizeof pm1);
        return ok;
    }

    bool coprimeToE(const u64* p) {
        u64 pm1[16], one[16] = { 1 };
        subN<16>(pm1, p, one);
        u64 a = 0;
        for (size_t i = 16; i-- > 0;) {
            u64 r;
            ctDivRem(a, pm1[i], kE, r);
            a = r;
        }
        secureZero(pm1, sizeof pm1);
        return a != 0;
    }

    bool isProbablePrime(const u64* p) {
        static const u64 kBases[8] = { 2, 3, 5, 7, 11, 13, 17, 19 };

        MontCtx<16> m;
        montInit<16>(m, p);
        u64 minusOne[16];
        subN<16>(minusOne, m.mod, m.one);

        u64 e[16], one[16] = { 1 };
        subN<16>(e, p, one);

        u64 zeroBelow[16];  
        for (size_t i = 0; i < 16; ++i) zeroBelow[i] = 0;
        u64 running = 1;
        for (size_t k = 0; k < 1024; ++k) {
            zeroBelow[k >> 6] |= running << (k & 63);
            running &= ((e[k >> 6] >> (k & 63)) & 1) ^ 1;
        }

        bool prime = true;
        for (size_t b = 0; b < 8 && prime; ++b) {
            u64 base[16], aM[16], r0[16], r1[16];
            zeroN<16>(base);
            base[0] = kBases[b];
            toMont<16>(m, aM, base);
            copyN<16>(r0, m.one);
            copyN<16>(r1, aM);

            u64 ok = 0;
            for (size_t k = 1024; k-- > 0;) {
                const u64 bit = (e[k >> 6] >> (k & 63)) & 1;
                const u64 mask = ctMask(bit);
                swapN<16>(mask, r0, r1);
                montMul<16>(m, r1, r0, r1);
                montMul<16>(m, r0, r0, r0);
                swapN<16>(mask, r0, r1);

                const u64 zb = (zeroBelow[k >> 6] >> (k & 63)) & 1;
                const u64 isOne = eqN<16>(r0, m.one);
                const u64 isMinus = eqN<16>(r0, minusOne);
                const u64 atS = bit & zb;                         
                const u64 belowS = (bit ^ 1) & zb & ctIsNonZero(k); 
                ok |= (atS & (isOne | isMinus)) | (belowS & isMinus);
            }
            prime = ok != 0;
        }
        return prime;
    }

    Status genPrime(u64* p, RSA::RandomFn rng, void* ctx) {
        u8 buf[RSA::kPrimeBytes], prev[RSA::kPrimeBytes];
        ZeroOnExit z1(buf, sizeof buf), z2(prev, sizeof prev);
        bool havePrev = false;
        for (unsigned attempt = 0; attempt < 10000; ++attempt) {
            if (!rng(ctx, buf, sizeof buf)) return Status::RngFailure;
            buf[0] |= 0xC0;
            buf[RSA::kPrimeBytes - 1] |= 1;
            if (havePrev && ctEqBytes(buf, prev, sizeof buf)) return Status::RngFailure;
            for (size_t i = 0; i < sizeof buf; ++i) prev[i] = buf[i];
            havePrev = true;

            fromBytes<16>(p, buf);
            if (!coprimeToE(p)) continue;
            if (isProbablePrime(p)) return Status::Ok;
        }
        return Status::RngFailure;
    }

    void mgf1Xor(const u8* seed, size_t seedLen, u8* dst, size_t dstLen) {
        u8 block[kHashLen];
        u8 ctr[4];
        for (size_t off = 0, c = 0; off < dstLen; off += kHashLen, ++c) {
            ctr[0] = static_cast<u8>(c >> 24);
            ctr[1] = static_cast<u8>(c >> 16);
            ctr[2] = static_cast<u8>(c >> 8);
            ctr[3] = static_cast<u8>(c);
            Sha3_512 h;
            h.update(seed, seedLen);
            h.update(ctr, sizeof ctr);
            h.finish(block);
            const size_t n = (dstLen - off < kHashLen) ? dstLen - off : kHashLen;
            for (size_t i = 0; i < n; ++i) dst[off + i] ^= block[i];
        }
        secureZero(block, sizeof block);
    }

    struct OaepBuf {
        u8 em[RSA::kModulusBytes];
        u8 lhash[kHashLen];
        OaepBuf() {
            for (size_t i = 0; i < sizeof em; ++i) em[i] = 0;
            for (size_t i = 0; i < sizeof lhash; ++i) lhash[i] = 0;
        }
        ~OaepBuf() {
            secureZero(em, sizeof em);
            secureZero(lhash, sizeof lhash);
        }
    };

    struct PrivTemps {
        u64 cp[16], cq[16], x[16], m1[16], m2[16], m2p[16], diff[16], h[16];
        u64 prod[32], add[32], m[32];
        ~PrivTemps() { secureZero(this, sizeof * this); }
    };

    struct KeyTemps {
        u64 n[32], qm[16], qM[16], pm2[16];
        ~KeyTemps() { secureZero(this, sizeof * this); }
    };

} 

RSA::RSA() { wipe(); }

RSA::~RSA() { wipe(); }

void RSA::wipe() {
    secureZero(&mn_, sizeof mn_);
    secureZero(&mp_, sizeof mp_);
    secureZero(&mq_, sizeof mq_);
    secureZero(dp_, sizeof dp_);
    secureZero(dq_, sizeof dq_);
    secureZero(qinv_, sizeof qinv_);
    hasPublic_ = false;
    hasPrivate_ = false;
}

RSA::Status RSA::loadPublicKey(const std::uint8_t* n) {
    if (n == nullptr) return Status::InvalidArgument;
    wipe();
    if (n[0] < 0x40 || (n[kModulusBytes - 1] & 1) == 0) return Status::InvalidKey;  
    u64 w[32];
    fromBytes<32>(w, n);
    montInit<32>(mn_, w);
    hasPublic_ = true;
    return Status::Ok;
}

RSA::Status RSA::loadPrivateKey(const std::uint8_t* p, const std::uint8_t* q) {
    if (p == nullptr || q == nullptr) return Status::InvalidArgument;
    u64 pw[16], qw[16];
    ZeroOnExit z1(pw, sizeof pw), z2(qw, sizeof qw);
    fromBytes<16>(pw, p);
    fromBytes<16>(qw, q);
    return setPrivate(pw, qw);
}

RSA::Status RSA::setPrivate(const u64* p, const u64* q) {
    wipe();
    if (((p[0] & q[0]) & 1) == 0) return Status::InvalidKey;                
    if (((p[15] & q[15]) >> 63) == 0) return Status::InvalidKey;            
    if (eqN<16>(p, q)) return Status::InvalidKey;

    KeyTemps k;
    mulFull<16>(k.n, p, q);
    montInit<32>(mn_, k.n);
    montInit<16>(mp_, p);
    montInit<16>(mq_, q);

    if (!crtExponent(p, dp_) || !crtExponent(q, dq_)) {
        wipe();
        return Status::InvalidKey;
    }

    copyN<16>(k.qm, q);
    reduceOnce<16>(k.qm, p);
    toMont<16>(mp_, k.qM, k.qm);
    const u64 two[16] = { 2 };
    subN<16>(k.pm2, p, two);
    montPow<16>(mp_, qinv_, k.qM, k.pm2);

    hasPublic_ = true;
    hasPrivate_ = true;

    u8 t0[kModulusBytes], t1[kModulusBytes], t2[kModulusBytes];
    ZeroOnExit z0(t0, sizeof t0), z1(t1, sizeof t1), z2(t2, sizeof t2);
    t0[0] = 0;
    for (size_t i = 1; i < kModulusBytes; ++i) t0[i] = static_cast<u8>(i * 7 + 3);
    if (rawPublic(t0, t1) != Status::Ok || rawPrivate(t1, t2) != Status::Ok ||
        ctEqBytes(t0, t2, kModulusBytes) == 0) {
        wipe();
        return Status::InvalidKey;
    }
    return Status::Ok;
}

RSA::Status RSA::generateKeys(RandomFn rng, void* rngCtx) {
    if (rng == nullptr) {
        rng = &RSA::systemRandom;
        rngCtx = nullptr;
    }
    u64 p[16], q[16];
    ZeroOnExit z1(p, sizeof p), z2(q, sizeof q);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        Status st = genPrime(p, rng, rngCtx);
        if (st != Status::Ok) return st;
        st = genPrime(q, rng, rngCtx);
        if (st != Status::Ok) return st;

        u64 d1[16], d2[16], d[16];
        const u64 borrow = subN<16>(d1, p, q);
        subN<16>(d2, q, p);
        selectN<16>(ctMask(borrow), d, d2, d1);
        if (d[15] == 0) continue;
        return setPrivate(p, q);
    }
    return Status::RngFailure;
}

RSA::Status RSA::getModulus(std::uint8_t* n) const {
    if (n == nullptr) return Status::InvalidArgument;
    if (!hasPublic_) return Status::InvalidKey;
    toBytes<32>(n, mn_.mod);
    return Status::Ok;
}

RSA::Status RSA::exportPrivateKey(std::uint8_t* p, std::uint8_t* q) const {
    if (p == nullptr || q == nullptr) return Status::InvalidArgument;
    if (!hasPrivate_) return Status::InvalidKey;
    toBytes<16>(p, mp_.mod);
    toBytes<16>(q, mq_.mod);
    return Status::Ok;
}

RSA::Status RSA::rawPublic(const std::uint8_t* in, std::uint8_t* out) const {
    if (in == nullptr || out == nullptr) return Status::InvalidArgument;
    if (!hasPublic_) return Status::InvalidKey;
    u64 x[32], r[32];
    fromBytes<32>(x, in);
    if (!ltN<32>(x, mn_.mod)) return Status::OutOfRange;
    publicPow(mn_, r, x);
    toBytes<32>(out, r);
    secureZero(x, sizeof x);
    secureZero(r, sizeof r);
    return Status::Ok;
}


RSA::Status RSA::rawPrivate(const std::uint8_t* in, std::uint8_t* out) const {
    if (in == nullptr || out == nullptr) return Status::InvalidArgument;
    if (!hasPrivate_) return Status::InvalidKey;

    u64 c[32];
    fromBytes<32>(c, in);
    if (!ltN<32>(c, mn_.mod)) return Status::OutOfRange;

    PrivTemps t;
    reduceWide(mp_, t.cp, c);
    reduceWide(mq_, t.cq, c);

    toMont<16>(mp_, t.x, t.cp);
    montPow<16>(mp_, t.x, t.x, dp_);
    fromMont<16>(mp_, t.m1, t.x);

    toMont<16>(mq_, t.x, t.cq);
    montPow<16>(mq_, t.x, t.x, dq_);
    fromMont<16>(mq_, t.m2, t.x);

    copyN<16>(t.m2p, t.m2);
    reduceOnce<16>(t.m2p, mp_.mod);                  
    modSub<16>(t.diff, t.m1, t.m2p, mp_.mod);        
    montMul<16>(mp_, t.h, t.diff, qinv_);            
    mulFull<16>(t.prod, t.h, mq_.mod);               
    zeroN<32>(t.add);
    copyN<16>(t.add, t.m2);
    addN<32>(t.m, t.prod, t.add);                    

    u64 back[32];
    publicPow(mn_, back, t.m);
    if (!eqN<32>(back, c)) return Status::FaultDetected;

    toBytes<32>(out, t.m);
    return Status::Ok;
}

RSA::Status RSA::sign(const std::uint8_t* digest, std::uint8_t* signature) const {
    return rawPrivate(digest, signature);
}

RSA::Status RSA::verify(const std::uint8_t* signature, const std::uint8_t* digest) const {
    if (digest == nullptr) return Status::InvalidArgument;
    u8 back[kModulusBytes];
    ZeroOnExit z(back, sizeof back);
    const Status st = rawPublic(signature, back);
    if (st != Status::Ok) return st;
    return ctEqBytes(back, digest, kModulusBytes) ? Status::Ok : Status::BadSignature;
}

RSA::Status RSA::encrypt(const std::uint8_t* msg, std::size_t msgLen,
    const std::uint8_t* label, std::size_t labelLen,
    std::uint8_t* cipher, RandomFn rng, void* rngCtx) const {
    if (cipher == nullptr || (msg == nullptr && msgLen != 0) || (label == nullptr && labelLen != 0)) {
        return Status::InvalidArgument;
    }
    if (!hasPublic_) return Status::InvalidKey;
    if (msgLen > kMaxMsg) return Status::MessageTooLong;
    if (rng == nullptr) {
        rng = &RSA::systemRandom;
        rngCtx = nullptr;
    }

    OaepBuf b;
    u8* seed = b.em + 1;
    u8* db = b.em + 1 + kHashLen;

    Sha3_512::hash(label, labelLen, db);
    const size_t psLen = kMaxMsg - msgLen;
    db[kHashLen + psLen] = 0x01;
    for (size_t i = 0; i < msgLen; ++i) db[kHashLen + psLen + 1 + i] = msg[i];

    if (!rng(rngCtx, seed, kHashLen)) return Status::RngFailure;

    mgf1Xor(seed, kHashLen, db, kDbLen);   
    mgf1Xor(db, kDbLen, seed, kHashLen);   

    return rawPublic(b.em, cipher);
}

RSA::Status RSA::decrypt(const std::uint8_t* cipher,
    const std::uint8_t* label, std::size_t labelLen,
    std::uint8_t* out, std::size_t outCap, std::size_t& outLen) const {
    outLen = 0;
    if (cipher == nullptr || out == nullptr || (label == nullptr && labelLen != 0) || outCap < kMaxMsg) {
        return Status::InvalidArgument;
    }
    if (!hasPrivate_) return Status::InvalidKey;

    OaepBuf b;
    Status st = rawPrivate(cipher, b.em);
    if (st == Status::OutOfRange) return Status::DecryptionError;  
    if (st != Status::Ok) return st;

    u8* seed = b.em + 1;
    u8* db = b.em + 1 + kHashLen;
    mgf1Xor(db, kDbLen, seed, kHashLen);  
    mgf1Xor(seed, kHashLen, db, kDbLen);  

    Sha3_512::hash(label, labelLen, b.lhash);
    u64 valid = ctIsZero(b.em[0]) & ctEqBytes(b.lhash, db, kHashLen);

    u8* rest = db + kHashLen;
    u64 found = 0, good = 0, idx = 0;
    for (size_t i = 0; i < kRestLen; ++i) {
        const u64 byte = rest[i];
        const u64 nz = ctIsNonZero(byte);
        const u64 first = (found ^ 1) & nz;
        good |= first & ctEq(byte, 1);
        idx = ctSelect(ctMask(first), static_cast<u64>(i), idx);
        found |= nz;
    }
    valid &= good;

    const u64 shift = idx + 1;
    for (unsigned s = 0; s < 7; ++s) {
        const u64 mask = ctMask((shift >> s) & 1);
        const size_t step = size_t{ 1 } << s;
        for (size_t i = 0; i < kRestLen; ++i) {
            const u8 moved = (i + step < kRestLen) ? rest[i + step] : static_cast<u8>(0);
            rest[i] = ctSelect8(mask, moved, rest[i]);
        }
    }

    const u64 vmask = ctMask(valid);
    for (size_t i = 0; i < kMaxMsg; ++i) out[i] = static_cast<u8>(rest[i] & vmask);
    outLen = static_cast<size_t>((kMaxMsg - idx) & vmask);

    return valid != 0 ? Status::Ok : Status::DecryptionError;
}

bool RSA::systemRandom(void*, void* buf, std::size_t len) {
    unsigned char* p = static_cast<unsigned char*>(buf);
#if defined(_WIN32)
    while (len > 0) {
        const ULONG chunk = len > 0x10000 ? 0x10000UL : static_cast<ULONG>(len);
        if (!SystemFunction036(p, chunk)) return false;
        p += chunk;
        len -= chunk;
    }
    return true;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(p, len);
    return true;
#else
#if defined(RSA_HAVE_GETRANDOM) && !defined(RSA_NO_GETRANDOM)
    while (len > 0) {
        const auto r = getrandom(p, len, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;  
        }
        p += r;
        len -= static_cast<std::size_t>(r);
    }
    if (len == 0) return true;
#endif
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = true;
    while (len > 0) {
        const auto r = read(fd, p, len);
        if (r < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (r == 0) {
            ok = false;
            break;
        }
        p += r;
        len -= static_cast<std::size_t>(r);
    }
    close(fd);
    return ok;
#endif
}
