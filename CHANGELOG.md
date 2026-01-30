# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-01-29
### Added
- **PSK (Pre-Shared Key) support**: All 21 recommended PSK patterns from the Noise
  Protocol specification are now supported. PSK patterns provide additional security
  through the use of pre-shared symmetric keys.
  - `psk0` variants: `Npsk0`, `Kpsk0`, `NNpsk0`, `NKpsk0`, `KNpsk0`, `KKpsk0`
  - `psk1` variants: `Xpsk1`, `INpsk1`, `IKpsk1`
  - `psk2` variants: `NNpsk2`, `NKpsk2`, `NXpsk2`, `KNpsk2`, `KKpsk2`, `KXpsk2`,
    `INpsk2`, `IKpsk2`, `IXpsk2`
  - `psk3` variants: `XNpsk3`, `XKpsk3`, `XXpsk3`
- New API options for PSK handshakes:
  - `{psk, binary()}` - Single pre-shared key (32 bytes)
  - `{psks, [binary()]}` - List of pre-shared keys (for patterns with multiple PSKs)

## [1.3.0] - 2026-01-29
### Added
- Support for 448 DH function and Blake2s hash function.
- Support for one-way patterns: `n`, `k`, and `x`.
- Support for deferred patterns: `nk1`, `nx1`, `x1n`, `x1k`, `xk1`, `x1k1`,
  `x1x`, `xx1`, `x1x1`, `k1n`, `k1k`, `kk1`, `k1k1`, `k1x`, `kx1`, `k1x1`,
  `i1n`, `i1k`, `ik1`, `i1k1`, `i1x`, `ix1`, and `i1x1`
- GitHub Actions CI pipeline.
### Changed
- **BREAKING**: OTP 27+ is now required.
- Using `crypto` over `enacl` (and removing a call to `get_stacktrace/1`) makes `enoise`
  up to date for (at least) OTP-27.
- Added test dependency `eqwalizer_support` to enable checking types with Eqwalizer.
- Replaced `jsx` test dependency with OTP's native `json` module.
### Removed
- The dependency on `enacl` is not needed anymore, OTP's `crypto` library now cover all
  necessary operations.
- Removed `jsx` test dependency (using OTP 27's `json` module instead).

## [1.2.0] - 2021-10-28
### Added
### Changed
- Use the new AEAD crypto interface introduced in OTP 22. This makes `enoise` OPT 24 compatible
  but it also means it no longer works on OTP 21 and earlier. You can't win them all.
- Fixed ChaChaPoly20 rekey
### Removed

## [1.1.0] - 2020-09-24
### Added
Include [Cacaphony](https://github.com/centromere/cacophony) test vectors.
### Changed
Updated `enacl` to version [1.1.1](https://github.com/jlouis/enacl/releases/tag/v1.1.1).
Fixed some imprecise type specifications.
### Removed

## [1.0.1] - 2018-12-21
### Added
### Changed
Improved argument checks and error handling in handshake (in particular related to empty
hand shake messages).
### Removed

## [1.0] - 2018-10-09
Initial version the following map describe what is supported:
```
#{ hs_pattern => [nn, kn, nk, kk, nx, kx, xn, in, xk, ik, xx, ix]
 , hash       => [blake2b, sha256, sha512]
 , cipher     => ['ChaChaPoly', 'AESGCM']
 , dh         => [dh25519] }
```

[1.4.0]: https://github.com/aeternity/enoise/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/aeternity/enoise/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/aeternity/enoise/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/aeternity/aesophia_cli/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/aeternity/aesophia_cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/aeternity/enoise/releases/tag/v1.0.0
