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

#pragma once

#include <simplesrp/details.h>
#include <simplesrp/bn.h>

namespace simplesrp {
    struct SRPRoutines {
        SRPRoutines();
        
        std::function<bn::BignumPtr(const SRPParams& params)> randomBN;
        std::function<bn::BignumPtr(const SRPParams& params, const BIGNUM* a)> calculate_A;
        std::function<bn::BignumPtr(const SRPParams& params, const BIGNUM* b, const BIGNUM* v, const BIGNUM* k)> calculate_B;
        std::function<bn::BignumPtr(const SRPParams& params)> calculate_k;
        std::function<bn::BignumPtr(const SRPParams& params, const std::string& username, const std::string& password, const Buffer& salt)> calculate_x;
        std::function<bn::BignumPtr(const SRPParams& params, const BIGNUM* A, const BIGNUM* B)> calculate_u;
        std::function<bn::BignumPtr(const SRPParams& params, const BIGNUM* u, const BIGNUM* x, const BIGNUM* k, const BIGNUM* a, const BIGNUM* B)> calculateClient_K;
        std::function<bn::BignumPtr(const SRPParams& params, const BIGNUM* u, const BIGNUM* v, const BIGNUM* b, const BIGNUM* A)> calculateServer_K;
        std::function<bn::BignumPtr(const SRPParams& params, const std::string& username, const Buffer& salt, const BIGNUM* A, const BIGNUM* B, const BIGNUM* K)> calculate_M1;
        std::function<bn::BignumPtr(const SRPParams& params, const BIGNUM* A, const BIGNUM* M, const BIGNUM* K)> calculate_M2;
        
        std::function<bool(const SRPParams& params, const BIGNUM* B, const BIGNUM* u)> clientSafetyCheck;
        std::function<bool(const SRPParams& params, const BIGNUM* A)> serverSafetyCheck;
        
        static std::function<const SRP_gN*(SRPBits bits)> gN;
    };
    
    namespace utils {
        class Digest {
        public:
            explicit Digest(DigestType digestType);
            void update(const void* ptr, size_t size);
            void update(const std::string& str);
            void update(const Buffer& buffer);
            Buffer final();
            
            Buffer hash(std::initializer_list<Buffer> buffers) const;
            Buffer hash(const std::string& str) const;
            size_t hashSize() const;
            
        private:
            union {
                SHA_CTX sha1;
                SHA256_CTX sha256;
                SHA512_CTX sha512;
            } m_ctx = {};
            DigestType m_digestType;
        };
    }
}
