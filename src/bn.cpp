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

#include <simplesrp/bn.h>

namespace simplesrp::bn {
    BignumPtr Own(BIGNUM* bn) {
        return std::shared_ptr<BIGNUM>(bn, BN_free);
    }
    
    BignumPtr Random(size_t size) {
        BignumPtr ptr = Own(BN_new());
        BN_rand(ptr.get(), static_cast<int>(size * 8), 0, 0);
        return ptr;
    }
    
    BignumPtr New() {
        return Own(BN_new());
    }
    
    BignumPtr FromBytes(const Buffer& data) {
        return FromBytes(data.data(), data.size());
    }
    
    BignumPtr FromBytes(const void* ptr, size_t size) {
        return Own(BN_bin2bn(static_cast<const uint8_t*>(ptr), static_cast<int>(size), NULL));
    }
    
    Buffer ToBytes(const BIGNUM* bn, size_t minSize) {
        Buffer bin(BN_num_bytes(bn));
        BN_bn2bin(bn, bin.data());
        
        const size_t binSize = bin.size();
        if (binSize < minSize)
        {
            bin.insert(bin.begin(), minSize - binSize, 0x00);
        }
        
        return bin;
    }
    
    Buffer ToBytes(BignumCPtr bn, size_t minSize) {
        return ToBytes(bn.get(), minSize);
    }
    
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> MakeContext() {
        return std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>(BN_CTX_new(), BN_CTX_free);
    };
}
