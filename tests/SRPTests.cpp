/*
 * MIT License
 *
 * Copyright (c) 2023 Alkenso (Vladimir Vashurkin)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <simplesrp/simplesrp.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace ::testing;
using namespace simplesrp;

class SRPTest: public TestWithParam<std::tuple<SRPBits, DigestType, Flags>> {};

INSTANTIATE_TEST_SUITE_P(
    AllSRPBitsAndDigestTypes,
    SRPTest,
    Combine(
        Values(
            SRPBits::Key1024,
            SRPBits::Key1536,
            SRPBits::Key2048,
            SRPBits::Key3072,
            SRPBits::Key4096,
            SRPBits::Key6144,
            SRPBits::Key8192
        ),
        Values(
            DigestType::SHA1,
            DigestType::SHA224,
            DigestType::SHA256,
            DigestType::SHA384,
            DigestType::SHA512
        ),
        Values(0)
    )
);

INSTANTIATE_TEST_SUITE_P(
    AllFlags,
    SRPTest,
    Combine(
        Values(SRPBits::Key4096),
        Values(DigestType::SHA256),
        Values(
            0,
            SRPFlagNoUsernameInX,
            SRPFlagNoUsernameInX | SRPFlagSkipZeroes_k_U_X,
            SRPFlagNoUsernameInX | SRPFlagSkipZeroes_M1_M2,
            SRPFlagNoUsernameInX | SRPFlagSkipZeroes_k_U_X | SRPFlagSkipZeroes_M1_M2,
            SRPFlagSkipZeroes_k_U_X,
            SRPFlagSkipZeroes_k_U_X | SRPFlagSkipZeroes_M1_M2,
            SRPFlagSkipZeroes_M1_M2
        )
    )
);


TEST_P(SRPTest, SRPAuthentication) {
    SRPBits srpBits = std::get<0>(GetParam());
    DigestType digestType = std::get<1>(GetParam());
    Flags flags = std::get<2>(GetParam());

    std::string username = "user@mail.com";
    std::string password = "password";
    
    SRPVerifierGenerator gen(digestType, srpBits);
    Buffer salt;
    Buffer verifier;
    gen.params.flags = flags;
    gen.generate(username, password, 20, salt, verifier);
    
    SRPClient client(digestType, srpBits);
    Buffer A;
    client.startAuthentication(A);
    client.params.flags = flags;
    
    SRPServer server(digestType, srpBits);
    server.params.flags = flags;
    Buffer B;
    server.startAuthentication(username, salt, verifier, B);
    
    Buffer M1;
    ASSERT_TRUE(client.processChallenge(username, password, salt, B, M1));
    
    Buffer M2;
    ASSERT_TRUE(server.verifySession(A, M1, M2));
    
    ASSERT_TRUE(client.verifySession(M2));
}
