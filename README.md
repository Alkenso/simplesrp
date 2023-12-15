# simplesrp
SRP 6a implementation in C++ compatible with Apple's `corecrypto` library.
Compatible with macOS, Windows, Linux.
Requires support of C++17 compiler but does NOT use any C++14/17 specific libraries.

SRP (Secure Remote Protocol) is auhtentication protocol that prevent
user password or its derivatives from being sent over the network.

It is covered by [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054) 
and [RFC2945](https://datatracker.ietf.org/doc/html/rfc2945).

`simplesrp` provides OpenSSL-based implementation of SRP 6a:
- SRPClient: client part of the protocol
- SRPServer: server part of the protocol
- SRPVerifierGenerator: functional to generate verifier (identity) on registration

## Build
CMake is used for build the library and tests.
Options:
- explicit OpenSSL dependency (if `find_package` fails in some reason): `-DOPENSSL_ROOT_DIR=/path/to/openssl`
- enable building of unit-tests: `-DSIMPLESRP_TESTING_ENABLE=ON`

```
mkdir build && cd build
cmake /path/to/simplesrp.git
make
```

## Example
```
using namespace simplesrp;

SRPBits srpBits = SRPBits::Key4096;
DigestType digestType = DigestType::SHA256;

std::string username = "user@mail.com";
std::string password = "password";

// First, create `verifier` based on user name and password.
// This is usually one-time action like registration.
//
// Usually you want to keep `username` + `verifier` + `salt` in the server database
// for future user authentication.
SRPVerifierGenerator generator(digestType, srpBits);
Buffer salt;
Buffer verifier;
generator.generate(username, password, 20, salt, verifier);

// Client starts authentication. (the operation is independent from Server).
SRPClient client(digestType, srpBits);
Buffer A;
client.startAuthentication(A);

// Server also starts authentication (the operation is independent from Client).
SRPServer server(digestType, srpBits);
Buffer B;
server.startAuthentication(username, salt, verifier, B);

// Client proceeds using Server public `B` and produce proof `M1`.
Buffer M1;
if (!client.processChallenge(username, password, salt, B, M1)) {
    error("Parameters are incorrect");
}

// Server verifies the session using proof `M1` and produce server proof `M2`.
// This step means the session is established.
// Now Server can use `server.sessionKey()` for payload encryption purposes.
Buffer M2;
if (!server.verifySession(A, M1, M2)) {
    error("Username or password is incorrect");
}

// Client verifies the session using server proof `M2`.
// This step means the session is established.
// Now Client can use `server.sessionKey()` for payload encryption purposes.
if (!client.verifySession(M2)) {
    error("Username or password is incorrect");
}
```

## Customization
For some reasons different implementations of SRP may require customization in
- generate randoms
- compute intermediate components (K, M, etc.)
- perform safety checks

All computations are encapsulated in `SRPRoutines` structure as std::function.
When needed, you may override one or more of them to achieve desired behaviour.
