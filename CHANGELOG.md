# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support for 448 DH function and Blake2s hash function.
### Changed
- Using `crypto` over `enacl` (and removing a call to `get_stacktrace/1`) makes `enoise`
  up to date for (at least) OTP-27.
### Removed
- The dependency on `enacl` is not needed anymore, OTP's `crypto` library now cover all
  necessary operations.

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

[Unreleased]: https://github.com/aeternity/aesophia_cli/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/aeternity/aesophia_cli/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/aeternity/aesophia_cli/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/aeternity/aesophia_cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/aeternity/enoise/releases/tag/v1.0.0
