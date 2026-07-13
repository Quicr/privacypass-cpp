# privacypass-cpp

[![CI](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

| Platform | Status |
|----------|--------|
| Linux | [![Linux](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml?query=branch%3Amain) |
| macOS | [![macOS](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml?query=branch%3Amain) |
| Windows | [![Windows](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml?query=branch%3Amain) |

C++ implementation of the Privacy Pass protocol ([RFC9576](https://datatracker.ietf.org/doc/html/rfc9576), [RFC9577](https://datatracker.ietf.org/doc/html/rfc9577), [RFC9578](https://datatracker.ietf.org/doc/html/rfc9578)) with optional MOQ extension ([draft-ietf-moq-privacy-pass-auth-02](https://datatracker.ietf.org/doc/html/draft-ietf-moq-privacy-pass-auth-02)) support.

## Features

- Blind RSA (Token Type 0x0002) and VOPRF P-384 (Token Type 0x0001)
- Token challenges, requests, responses, and redemption
- Optional MOQ extension ([draft-ietf-moq-privacy-pass-auth-02](https://datatracker.ietf.org/doc/html/draft-ietf-moq-privacy-pass-auth-02))
- Modern C++23 with `std::expected` error handling
- Pluggable crypto backend: OpenSSL 3.x or BoringSSL ([details](docs/crypto_backend.md))

## Building

Requires CMake 3.20+, C++23 compiler, and OpenSSL 3.x or BoringSSL.
See [docs/crypto_backend.md](docs/crypto_backend.md) for multi-backend setup.

```bash
cmake -B build
cmake --build build --parallel
```

Or with [just](https://github.com/casey/just):

```bash
just build          # Build with MOQ extension (default)
just moq=OFF build  # Build without MOQ extension
```

## Testing

```bash
just test
# or
./build/privacy_pass_tests
```

## License

BSD-2-Clause. See [LICENSE](LICENSE).
