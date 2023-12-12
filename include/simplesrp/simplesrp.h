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
#include <simplesrp/routines.h>

namespace simplesrp {
    class SRPClient {
    public:
        SRPClient(DigestType digestType, SRPBits srpBits);
        
        SRPParams params;
        SRPRoutines routines;
        
        void startAuthentication(Buffer& A);
        bool processChallenge(const std::string& username, const std::string& password,
                              const Buffer& salt, const Buffer& B,
                              Buffer& M1, Buffer* _M2 = nullptr);
        bool verifySession(const Buffer& M2);
        
        Buffer sessionKey() const;
        
        /// Alternative version that accept private portion of exchange data.
        /// Using weak or hardcoded private data may break the security of the app.
        void insecure_startAuthentication(const Buffer& a, Buffer& A);
        
    private:
        bn::BignumPtr m_a;
        bn::BignumPtr m_A;
        bn::BignumPtr m_K;
        bn::BignumPtr m_M1;
    };
    
    class SRPServer
    {
    public:
        SRPServer(DigestType digestType, SRPBits srpBits);
        
        SRPParams params;
        SRPRoutines routines;
        
        void startAuthentication(const std::string& username, const Buffer& salt, const Buffer& verifier, Buffer& B);
        bool verifySession(const Buffer& A, const Buffer& M1, Buffer& M2);
        
        Buffer sessionKey();
        
    private:
        std::string m_username;
        Buffer m_salt;
        bn::BignumPtr m_v;
        bn::BignumPtr m_b;
        bn::BignumPtr m_B;
        bn::BignumPtr m_K;
    };
    
    class SRPVerifierGenerator {
    public:
        SRPVerifierGenerator(DigestType digestType, SRPBits srpBits);
        
        SRPParams params;
        SRPRoutines routines;
        
        void generate(const std::string& username, const std::string& password,
                      const size_t saltSize, Buffer& salt, Buffer& verifier);
        
        void generate(const std::string& username, const std::string& password,
                      const Buffer& salt, Buffer& verifier);
    };
}
