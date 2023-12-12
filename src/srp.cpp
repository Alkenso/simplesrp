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

#include <simplesrp/simplesrp.h>

using namespace simplesrp;

namespace {
    SRPParams CreateParams(DigestType digestType, SRPBits srpBits) {
        static const std::map<SRPBits, const char*> s_srpBits = {
            { SRPBits::Key1024, "1024" },
            { SRPBits::Key1536, "1536" },
            { SRPBits::Key2048, "2048" },
            { SRPBits::Key3072, "3072" },
            { SRPBits::Key4096, "4096" },
            { SRPBits::Key6144, "6144" },
            { SRPBits::Key8192, "8192" }
        };
        
        SRPParams params;
        params.digestType = digestType;
        params.gn = SRPRoutines::gN(srpBits);
        return params;
    }
}

// === SRPClient ===

SRPClient::SRPClient(DigestType digestType, SRPBits srpBits)
: params(CreateParams(digestType, srpBits))
{}

void SRPClient::startAuthentication(Buffer& A) {
    insecure_startAuthentication({}, A);
}

void SRPClient::insecure_startAuthentication(const Buffer& a, Buffer& A) {
    if (!a.empty()) {
        m_a = bn::FromBytes(a);
    }
    if (!m_a || BN_num_bytes(m_a.get()) != BN_num_bytes(params.gn->N)) {
        m_a = routines.randomBN(params);
    }
    m_A = routines.calculate_A(params, m_a.get());
    A = bn::ToBytes(m_A.get());
}

bool SRPClient::processChallenge(const std::string& username, const std::string& password,
                                 const Buffer& salt, const Buffer& _B,
                                 Buffer& _M1, Buffer* _M2 /* = nullptr */) {
    auto B = bn::FromBytes(_B);
    auto u = routines.calculate_u(params, m_A.get(), B.get());
    if (!routines.clientSafetyCheck(params, B.get(), u.get())) {
        return false;
    }
    
    auto x = routines.calculate_x(params, username, password, salt);
    
    auto k = routines.calculate_k(params);
    m_K = routines.calculateClient_K(params, u.get(), x.get(), k.get(), m_a.get(), B.get());
    m_M1 = routines.calculate_M1(params, username, salt, m_A.get(), B.get(), m_K.get());
    
    _M1 = bn::ToBytes(m_M1.get());
    if (_M2) {
        auto M2 = routines.calculate_M2(params, m_A.get(), m_M1.get(), m_K.get());
        *_M2 = bn::ToBytes(M2);
    }
    
    return !_M1.empty();
}

bool SRPClient::verifySession(const Buffer& M2) {
    auto clientM2 = routines.calculate_M2(params, m_A.get(), m_M1.get(), m_K.get());
    Buffer clientM2Bytes = bn::ToBytes(clientM2);
    return clientM2Bytes == M2;
}

Buffer SRPClient::sessionKey() const {
    return m_K ? bn::ToBytes(m_K) : Buffer();
}

// === SRPServer ===

SRPServer::SRPServer(DigestType digestType, SRPBits srpBits) 
: params(CreateParams(digestType, srpBits))
{}

void SRPServer::startAuthentication(const std::string& username, const Buffer& salt, const Buffer& verifier, Buffer& B) {
    m_username = username;
    m_salt = salt;
    m_v = bn::FromBytes(verifier);
    m_b = routines.randomBN(params);
    
    auto k = routines.calculate_k(params);
    m_B = routines.calculate_B(params, m_b.get(), m_v.get(), k.get());
    B = bn::ToBytes(m_B.get());
}

bool SRPServer::verifySession(const Buffer& _A, const Buffer& M1, Buffer& _M2) {
    auto A = bn::FromBytes(_A);
    if (!routines.serverSafetyCheck(params, A.get())) {
        return false;
    }
    
    auto u = routines.calculate_u(params, A.get(), m_B.get());
    m_K = routines.calculateServer_K(params, u.get(), m_v.get(), m_b.get(), A.get());
    
    auto serverM1 = routines.calculate_M1(params, m_username, m_salt, A.get(), m_B.get(), m_K.get());
    Buffer serverM1Bytes = bn::ToBytes(serverM1.get());
    if (serverM1Bytes != M1) {
        return false;
    }
    
    auto M2 = routines.calculate_M2(params, A.get(), serverM1.get(), m_K.get());
    _M2 = bn::ToBytes(M2.get());
    return true;
}


Buffer SRPServer::sessionKey() {
    return m_K ? bn::ToBytes(m_K) : Buffer();
}

// === SRPVerifierGenerator ===

SRPVerifierGenerator::SRPVerifierGenerator(DigestType digestType, SRPBits srpBits)
: params(CreateParams(digestType, srpBits))
{}

void SRPVerifierGenerator::generate(const std::string& username, const std::string& password,
                                    const size_t saltSize, Buffer& _salt, Buffer& _verifier) {
    auto salt = bn::Random(saltSize);
    _salt = bn::ToBytes(salt.get(), saltSize);
    generate(username, password, _salt, _verifier);
}

void SRPVerifierGenerator::generate(const std::string& username, const std::string& password,
                                    const Buffer& salt, Buffer& _verifier) {
    auto x = routines.calculate_x(params, username, password, salt);
    auto verifier = routines.calculate_A(params, x.get());
    _verifier = bn::ToBytes(verifier);
}
