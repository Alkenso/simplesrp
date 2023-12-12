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

#include <openssl/srp.h>
#include <openssl/sha.h>

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace simplesrp {
    using Buffer = std::vector<uint8_t>;
    
    enum class SRPBits {
        Key1024,
        Key1536,
        Key2048,
        Key3072,
        Key4096,
        Key6144,
        Key8192,
    };
    
    enum class DigestType {
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
    };
    
    enum Flags {
        // Shared secret will be calculated without username, but rest calculations uses original username.
        SRPFlagNoUsernameInX = 1 << 0,
        
        // Skip zeroes of A and B during hashes for the computation of k, U and X.
        SRPFlagSkipZeroes_k_U_X = 1 << 1,
        
        // Skip leading zeroes when hashing A, B in M and HAMK only.
        // This is a hack to be compatible with AppleSRP implementation.
        SRPFlagSkipZeroes_M1_M2 = 1 << 2,
    };
    
    inline Flags operator&(Flags lhs, Flags rhs) {
        using T = std::underlying_type_t<Flags>;
        return static_cast<Flags>(static_cast<T>(lhs) & static_cast<T>(rhs));
    }
    
    inline Flags& operator&=(Flags& lhs, Flags rhs) {
        lhs = lhs & rhs;
        return lhs;
    }
    
    inline Flags operator|(Flags lhs, Flags rhs) {
        using T = std::underlying_type_t<Flags>;
        return static_cast<Flags>(static_cast<T>(lhs) | static_cast<T>(rhs));
    }
    
    inline Flags& operator|=(Flags& lhs, Flags rhs) {
        lhs = lhs | rhs;
        return lhs;
    }
    
    struct SRPParams {
        const SRP_gN* gn;
        DigestType digestType;
        Flags flags = {};
    };
}
