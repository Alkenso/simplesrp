//  MIT License
//
//  Copyright (c) 2023 Alkenso (Vladimir Vashurkin)
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

#include <simplesrp/routines.h>

#if defined(_MSC_VER)
#define SSRP_DISABLE_DEPRECATION_WARNINGS \
    __pragma(warning(push)) \
    __pragma(warning(disable : 4996))
#define SSRP_ENABLE_DEPRECATION_WARNINGS \
    __pragma(warning(pop))

#elif defined(__GNUC__) || defined(__clang__)
#define SSRP_DISABLE_DEPRECATION_WARNINGS \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define SSRP_ENABLE_DEPRECATION_WARNINGS \
    _Pragma("GCC diagnostic pop")

#else
#define SSRP_DISABLE_DEPRECATION_WARNINGS
#define SSRP_ENABLE_DEPRECATION_WARNINGS
#endif

namespace {
    using namespace simplesrp;
    
    size_t MinBignumSize(const SRPParams& params, Flags flag) {
        return (params.flags & flag) ? 0 : BN_num_bytes(params.gn->N);
    }
    
    bn::BignumPtr RandomBN(const SRPParams& params) {
        return bn::Random(BN_num_bytes(params.gn->N));
    }
    
    bn::BignumPtr Calculate_A(const SRPParams& params, const BIGNUM* a) {
        auto A = bn::New();
        auto ctx = bn::MakeContext();
        BN_mod_exp(A.get(), params.gn->g, a, params.gn->N, ctx.get());
        
        return A;
    }
    
    bn::BignumPtr Calculate_B(const SRPParams& params, const BIGNUM* b, const BIGNUM* v, const BIGNUM* k) {
        auto tmp1 = bn::New();
        auto tmp2 = bn::New();
        auto B = bn::New();
        
        auto ctx = bn::MakeContext();

        /* B = kv + g^b */
        BN_mul(tmp1.get(), k, v, ctx.get());
        BN_mod_exp(tmp2.get(), params.gn->g, b, params.gn->N, ctx.get());
        BN_mod_add(B.get(), tmp1.get(), tmp2.get(), params.gn->N, ctx.get());

        return B;
    }
    
    bn::BignumPtr Calculate_k(const SRPParams& params) {
        const size_t bnSize = MinBignumSize(params, SRPFlagSkipZeroes_k_U_X);
        auto result = utils::Digest(params.digestType).hash({
            bn::ToBytes(params.gn->N, bnSize),
            bn::ToBytes(params.gn->g, bnSize),
        });
        return bn::FromBytes(result);
    }
    
    bn::BignumPtr Calculate_x(const SRPParams& params, const std::string& username, const std::string& password, const Buffer& salt) {
        utils::Digest di(params.digestType);
        if (!(params.flags & SRPFlagNoUsernameInX)) {
            di.update(username);
        }
        di.update(":");
        di.update(password);
        
        auto hash = di.final();
        auto x = utils::Digest(params.digestType).hash({
            salt,
            hash,
        });
        return bn::FromBytes(x);
    }
    
    bn::BignumPtr Calculate_u(const SRPParams& params, const BIGNUM* A, const BIGNUM* B) {
        const size_t bnSize = MinBignumSize(params, SRPFlagSkipZeroes_k_U_X);
        auto result = utils::Digest(params.digestType).hash({
            bn::ToBytes(A, bnSize),
            bn::ToBytes(B, bnSize),
        });
        return bn::FromBytes(result);
    }
    
    bn::BignumPtr CalculateClient_K(const SRPParams& params, const BIGNUM* u, const BIGNUM* x, const BIGNUM* k, const BIGNUM* a, const BIGNUM* B) {
        auto v = bn::New();
        auto K = bn::New();
        auto tmp1 = bn::New();
        auto tmp2 = bn::New();
        auto tmp3 = bn::New();
        
        auto ctx = bn::MakeContext();
        BN_mod_exp(v.get(), params.gn->g, x, params.gn->N, ctx.get());
        
        // S = (B - k*(g^x)) ^ (a + ux)
        BN_mul(tmp1.get(), u, x, ctx.get());
        BN_add(tmp2.get(), a, tmp1.get());                       // tmp2 = (a + ux)
        BN_mod_exp(tmp1.get(), params.gn->g, x, params.gn->N, ctx.get());
        BN_mul(tmp3.get(), k, tmp1.get(), ctx.get());            // tmp3 = k*(g^x)
        BN_sub(tmp1.get(), B, tmp3.get());                       // tmp1 = (B - K*(g^x))
        BN_mod_exp(K.get(), tmp1.get(), tmp2.get(), params.gn->N, ctx.get());
        
        auto result = utils::Digest(params.digestType).hash({ bn::ToBytes(K.get()) });
        return bn::FromBytes(result);
    }
    
    bn::BignumPtr CalculateServer_K(const SRPParams& params, const BIGNUM* u, const BIGNUM* v, const BIGNUM* b, const BIGNUM* A) {
        auto tmp1 = bn::New();
        auto tmp2 = bn::New();
        auto K = bn::New();
        auto ctx = bn::MakeContext();
        
        // S = (A *(v^u)) ^ b
        BN_mod(tmp1.get(), A, params.gn->N, ctx.get());
        BN_mod_exp(tmp1.get(), v, u, params.gn->N, ctx.get());
        BN_mul(tmp2.get(), A, tmp1.get(), ctx.get());
        BN_mod_exp(K.get(), tmp2.get(), b, params.gn->N, ctx.get());
        
        auto result = utils::Digest(params.digestType).hash({ bn::ToBytes(K.get()) });
        return bn::FromBytes(result);
    }
    
    bn::BignumPtr Calculate_M1(const SRPParams& params, const std::string& username, const Buffer& salt, const BIGNUM* A, const BIGNUM* B, const BIGNUM* K) {
        const size_t bnSize = MinBignumSize(params, SRPFlagSkipZeroes_M1_M2);
        auto gBytes = bn::ToBytes(params.gn->g, bnSize);
        auto nBytes = bn::ToBytes(params.gn->N, bnSize);
        
        const utils::Digest di(params.digestType);
        const auto hashG = di.hash({ gBytes });
        const auto hashN = di.hash({ nBytes });
        
        const size_t hashSize = di.hashSize();
        Buffer hashXor(hashSize);
        for (size_t i = 0; i < hashSize; i++)
        {
            hashXor[i] = hashN[i] ^ hashG[i];
        }
        
        const Buffer& hashI = di.hash(username);
        
        utils::Digest di_M1(params.digestType);
        di_M1.update(hashXor);
        di_M1.update(hashI);
        di_M1.update(salt);
        di_M1.update(bn::ToBytes(A, bnSize));
        di_M1.update(bn::ToBytes(B, bnSize));
        di_M1.update(bn::ToBytes(K));
        
        auto M1 = di_M1.final();
        return bn::FromBytes(M1);
    }
    
    bn::BignumPtr Calculate_M2(const SRPParams& params, const BIGNUM* A, const BIGNUM* M, const BIGNUM* K) {
        const size_t bnSize = MinBignumSize(params, SRPFlagSkipZeroes_M1_M2);
        utils::Digest di_M2(params.digestType);
        di_M2.update(bn::ToBytes(A, bnSize));
        di_M2.update(bn::ToBytes(M));
        di_M2.update(bn::ToBytes(K));
        
        auto M2 = di_M2.final();
        return bn::FromBytes(M2);
    }
    
    bool ClientSafetyCheck(const SRPParams& params, const BIGNUM* B, const BIGNUM* u) {
        return !BN_is_zero(B) && !BN_is_zero(u);
    }
    
    bool ServerSafetyCheck(const SRPParams& params, const BIGNUM* A) {
        auto ctx = bn::MakeContext();
        auto tmp = bn::New();
        BN_mod(tmp.get(), A, params.gn->N, ctx.get());
        
        return !BN_is_zero(tmp.get());
    }
    
    SRP_gN* gN(SRPBits bits) {
        static const std::map<SRPBits, const char*> s_srpBits = {
            { SRPBits::Key1024, "1024" },
            { SRPBits::Key1536, "1536" },
            { SRPBits::Key2048, "2048" },
            { SRPBits::Key3072, "3072" },
            { SRPBits::Key4096, "4096" },
            { SRPBits::Key6144, "6144" },
            { SRPBits::Key8192, "8192" }
        };
        
        auto it = s_srpBits.find(bits);
        if (it == s_srpBits.end()) {
            return nullptr;
        }
        
        SSRP_DISABLE_DEPRECATION_WARNINGS
        return SRP_get_default_gN(it->second);
        SSRP_ENABLE_DEPRECATION_WARNINGS
    }
}

std::function<const SRP_gN*(SRPBits bits)> simplesrp::SRPRoutines::gN = ::gN;

simplesrp::SRPRoutines::SRPRoutines()
: randomBN(::RandomBN)
, calculate_A(::Calculate_A)
, calculate_B(::Calculate_B)
, calculate_k(::Calculate_k)
, calculate_x(::Calculate_x)
, calculate_u(::Calculate_u)
, calculateClient_K(::CalculateClient_K)
, calculateServer_K(::CalculateServer_K)
, calculate_M1(::Calculate_M1)
, calculate_M2(::Calculate_M2)
, clientSafetyCheck(::ClientSafetyCheck)
, serverSafetyCheck(::ServerSafetyCheck)
{}


utils::Digest::Digest(DigestType digestType)
: m_digestType(digestType)
{
    SSRP_DISABLE_DEPRECATION_WARNINGS
    switch (m_digestType) {
    case DigestType::SHA1:
        SHA1_Init(&m_ctx.sha1);
        break;
    case DigestType::SHA224:
        SHA224_Init(&m_ctx.sha256);
        break;
    case DigestType::SHA256:
        SHA256_Init(&m_ctx.sha256);
        break;
    case DigestType::SHA384:
        SHA384_Init(&m_ctx.sha512);
        break;
    case DigestType::SHA512:
        SHA512_Init(&m_ctx.sha512);
        break;
    default:
        break;
    }
    SSRP_ENABLE_DEPRECATION_WARNINGS
}

void utils::Digest::update(const void* ptr, size_t size) {
    SSRP_DISABLE_DEPRECATION_WARNINGS
    switch (m_digestType) {
    case DigestType::SHA1:
        SHA1_Update(&m_ctx.sha1, ptr, size);
        break;
    case DigestType::SHA224:
        SHA224_Update(&m_ctx.sha256, ptr, size);
        break;
    case DigestType::SHA256:
        SHA256_Update(&m_ctx.sha256, ptr, size);
        break;
    case DigestType::SHA384:
        SHA384_Update(&m_ctx.sha512, ptr, size);
        break;
    case DigestType::SHA512:
        SHA512_Update(&m_ctx.sha512, ptr, size);
        break;
    default:
        break;
    }
    SSRP_ENABLE_DEPRECATION_WARNINGS
}

void utils::Digest::update(const std::string& str) {
    update(str.data(), str.size());
}

void utils::Digest::update(const Buffer& buffer) {
    update(buffer.data(), buffer.size());
}

Buffer utils::Digest::final() {
    Buffer hash(hashSize());
    SSRP_DISABLE_DEPRECATION_WARNINGS
    switch (m_digestType) {
    case DigestType::SHA1:
        SHA1_Final(hash.data(), &m_ctx.sha1);
        break;
    case DigestType::SHA224:
        SHA224_Final(hash.data(), &m_ctx.sha256);
        break;
    case DigestType::SHA256:
        SHA256_Final(hash.data(), &m_ctx.sha256);
        break;
    case DigestType::SHA384:
        SHA384_Final(hash.data(), &m_ctx.sha512);
        break;
    case DigestType::SHA512:
        SHA512_Final(hash.data(), &m_ctx.sha512);
        break;
    default:
        break;
    }
    SSRP_ENABLE_DEPRECATION_WARNINGS
    
    return hash;
}

Buffer utils::Digest::hash(std::initializer_list<Buffer> buffers) const {
    Digest di(m_digestType);
    for (const auto& buffer : buffers) {
        di.update(buffer);
    }
    return di.final();
}

Buffer utils::Digest::hash(const std::string& str) const {
    return hash({ Buffer(str.begin(), str.end()) });
}

size_t utils::Digest::hashSize() const {
    switch (m_digestType) {
    case DigestType::SHA1: return SHA_DIGEST_LENGTH;
    case DigestType::SHA224: return SHA224_DIGEST_LENGTH;
    case DigestType::SHA256: return SHA256_DIGEST_LENGTH;
    case DigestType::SHA384: return SHA384_DIGEST_LENGTH;
    case DigestType::SHA512: return SHA512_DIGEST_LENGTH;
    default: return 0;
    }
}
