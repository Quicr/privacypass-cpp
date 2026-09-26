# Crypto Backend Benchmarks

Comparison of OpenSSL 3.x vs BoringSSL on Apple M-series (10-core, ARM64).
All numbers are median CPU time from 3 repetitions using Google Benchmark.

## Hash Functions

| Operation | OpenSSL | BoringSSL | Ratio |
|---|--:|--:|---|
| SHA-256 (32 B) | 156 ns | 45 ns | **3.5x BoringSSL** |
| SHA-256 (256 B) | 219 ns | 122 ns | **1.8x BoringSSL** |
| SHA-256 (1 KB) | 437 ns | 346 ns | **1.3x BoringSSL** |
| SHA-256 (4 KB) | 1349 ns | 1256 ns | 1.1x BoringSSL |
| SHA-384 (32 B) | 206 ns | 100 ns | **2.1x BoringSSL** |
| SHA-384 (256 B) | 335 ns | 238 ns | **1.4x BoringSSL** |
| SHA-384 (1 KB) | 738 ns | 654 ns | 1.1x BoringSSL |
| HMAC-SHA-256 (32 B) | 606 ns | 108 ns | **5.6x BoringSSL** |
| HMAC-SHA-256 (1 KB) | 904 ns | 413 ns | **2.2x BoringSSL** |
| HKDF-Extract | 1628 ns | 115 ns | **14.2x BoringSSL** |
| HKDF-Expand | 1652 ns | 185 ns | **8.9x BoringSSL** |

BoringSSL's hash primitives are significantly faster, especially for small
inputs typical in Privacy Pass (challenge digests, key IDs, HMAC). The HKDF
advantage is dramatic because OpenSSL 3.x routes through the EVP_PKEY_CTX
provider layer while BoringSSL calls the primitives directly.

## Blind RSA (Privacy Pass Public Verification)

| Operation | OpenSSL | BoringSSL | Ratio |
|---|--:|--:|---|
| KeyGen | 24.7 ms | 40.6 ms | **1.6x OpenSSL** |
| Blind (client) | 191 us | 135 us | **1.4x BoringSSL** |
| BlindSign (issuer) | 1036 us | 1095 us | ~same |
| **Verify (relay)** | **12.1 us** | **8.1 us** | **1.5x BoringSSL** |
| Full Protocol | 1248 us | 1253 us | ~same |

For a MoQ relay, **Verify is the hot-path operation** -- it runs on every
token redemption. BoringSSL's 8.1 us verify means a single core can verify
~123K tokens/sec, vs ~83K/sec with OpenSSL.

BlindSign (issuer-side) is the bottleneck at ~1 ms regardless of backend,
limited by RSA-2048 modular exponentiation with the private key.

## VOPRF P-384 (Privacy Pass Private Verification)

| Operation | OpenSSL | BoringSSL | Ratio |
|---|--:|--:|---|
| KeyGen | 65 us | 202 us | **3.1x OpenSSL** |
| Blind (client) | 245 us | 309 us | **1.3x OpenSSL** |
| Evaluate (issuer) | 818 us | 1409 us | **1.7x OpenSSL** |
| Full Protocol | 2358 us | 3695 us | **1.6x OpenSSL** |

OpenSSL's P-384 elliptic curve implementation is consistently faster.
This matters for VOPRF-based private verification flows but is less
relevant for MoQ relays that typically use Blind RSA.

## Serialization (backend-independent)

| Operation | Time | Throughput |
|---|--:|---|
| TokenChallenge Digest (cached) | 1.0 ns | cache hit |
| Token Deserialize (Blind RSA) | 27 ns | ~37M tokens/sec |
| Token Serialize (Blind RSA) | 50 ns | ~20M tokens/sec |
| TokenChallenge Serialize | 51 ns | |
| TokenChallenge Deserialize | 64 ns | |

Serialization is not a bottleneck. The cached challenge digest returns in
~1 ns after the first computation.

## Random Number Generation

| Operation | OpenSSL | BoringSSL | Ratio |
|---|--:|--:|---|
| 32 bytes | 155 ns | 198 ns | 1.3x OpenSSL |
| 256 bytes | 167 ns | 221 ns | 1.3x OpenSSL |
| 1 KB | 233 ns | 294 ns | 1.3x OpenSSL |

OpenSSL is slightly faster for RNG. Both backends use OS entropy sources
under the hood.

## Relay Throughput Estimates

For a MoQ relay verifying Blind RSA tokens on a 10-core machine:

| Backend | Verify/core | 10-core throughput |
|---|--:|--:|
| OpenSSL | ~83K tok/sec | ~830K tok/sec |
| BoringSSL | ~123K tok/sec | ~1.23M tok/sec |

These numbers exclude replay cache overhead, deserialization, and network I/O.
With the time-bucketed replay cache, the non-crypto overhead adds < 1 us per
token at steady state.

## Which Backend to Choose

| Workload | Recommended |
|---|---|
| Blind RSA relay (token verification) | **BoringSSL** |
| Blind RSA issuer (signing) | Either (same speed) |
| VOPRF issuer/evaluator | **OpenSSL** |
| Hash-heavy / HKDF-heavy | **BoringSSL** |
| Key generation (infrequent) | OpenSSL |

## Running Benchmarks

```bash
# OpenSSL
just backend=openssl bench

# BoringSSL
just backend=boringssl bench

# Side-by-side provider benchmarks
just bench-all

# Save results as JSON for comparison
just bench-all-json
```
