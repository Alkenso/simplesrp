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

#include <openssl/bn.h>
#include <memory>

namespace simplesrp::bn {
    using BignumPtr = std::shared_ptr<BIGNUM>;
    using BignumCPtr = std::shared_ptr<const BIGNUM>;
    
    BignumPtr Own(BIGNUM* bn);
    BignumPtr New();
    BignumPtr Random(size_t size);
    BignumPtr FromBytes(const Buffer& data);
    BignumPtr FromBytes(const void* ptr, size_t size);
    
    Buffer ToBytes(const BIGNUM* bn, size_t minSize = 0);
    Buffer ToBytes(BignumCPtr bn, size_t minSize = 0);
    
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> MakeContext();
}
