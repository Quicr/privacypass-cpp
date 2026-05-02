# privacypass-cpp

[![CI](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/Quicr/privacypass-cpp/actions/workflows/ci.yml)

C++ implementation of the Privacy Pass protocol (RFC 9576-9578) with optional MOQ extension support.

## Features

- Blind RSA (Token Type 0x0002) and VOPRF P-384 (Token Type 0x0001)
- Token challenges, requests, responses, and redemption
- Optional MOQ extension (draft-ietf-moq-privacy-pass-auth)
- Modern C++23 with `std::expected` error handling

## Building

Requires CMake 3.20+, C++23 compiler, and OpenSSL 3.x.

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
