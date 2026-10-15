# Supported SSH Algorithms

This document lists the authentication methods, cryptographic algorithms, and
compression options supported by the ConnectBot SSH library.

Algorithms labeled **legacy opt-in** are implemented for compatibility but are
not offered by the default `SshClientConfig`. Applications must add them
explicitly to the corresponding algorithm string.

The lists below enumerate support, not negotiation preference order. Configure
the ordered, comma-separated `kexAlgorithms`, `hostKeyAlgorithms`,
`encryptionAlgorithms`, and `macAlgorithms` strings in `SshClientConfig` to
override the defaults.

## Authentication

- `keyboard-interactive`
- `password`
- `publickey` (including FIDO2 / Security Key algorithms `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`)

Security Key authentication requires a caller-provided FIDO2/CTAP2 stack; the
library supplies SSH encoding helpers. See [Security Key authentication](SK_AUTH.md).

RSA public key authentication selects `rsa-sha2-512` or `rsa-sha2-256` from the
server's `server-sig-algs` extension and the configured `hostKeyAlgorithms`.
Legacy `ssh-rsa` (RSA/SHA-1) authentication requires explicit opt-in through
`hostKeyAlgorithms`; without `server-sig-algs`, only that explicitly enabled
base-key algorithm is used.

## Host Keys

- `ssh-mldsa87-p384` ([SSH composite signatures draft](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-composite-sigs-00)) — requires platform support
- `ssh-mldsa44-ed25519` ([SSH composite signatures draft](https://datatracker.ietf.org/doc/draft-ietf-sshm-composite-sigs/00/)) — requires platform support
- `ssh-mldsa-44` ([SSH ML-DSA draft](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/08/)) — requires platform support, opt-in
- `ssh-mldsa-65` ([SSH ML-DSA draft](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/08/)) — requires platform support, opt-in
- `ssh-mldsa-87` ([SSH ML-DSA draft](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/08/)) — requires platform support, opt-in
- `ssh-ed25519` ([RFC 8709](https://tools.ietf.org/html/rfc8709))
- `ssh-ed448` ([RFC 8709](https://tools.ietf.org/html/rfc8709))
- `ecdsa-sha2-nistp256` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
- `ecdsa-sha2-nistp384` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
- `ecdsa-sha2-nistp521` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
- `rsa-sha2-512` ([RFC 8332](https://tools.ietf.org/html/rfc8332#section-3))
- `rsa-sha2-256` ([RFC 8332](https://tools.ietf.org/html/rfc8332#section-3))
- `ssh-rsa` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1)) — **legacy opt-in**

ML-DSA requires a capable installed JCA provider. On Android, call Google Play
Services' `ProviderInstaller.installIfNeeded` before creating `SshClientConfig`
to use its updated security provider. Composite host keys are offered by default
when available; pure ML-DSA host keys require an explicit `hostKeyAlgorithms` setting.

For `ssh-mldsa87-p384` private keys, use PEM; OpenSSH private-key format is not
supported.

Pure ML-DSA does not have a defined OpenSSH private-key layout; use PKCS#8 PEM.
ML-DSA PEM imports require an embedded public key or an appended `PUBLIC KEY`
PEM block.

## Key Exchange

- `mlkem768x25519-sha256` ([RFC 10042](https://datatracker.ietf.org/doc/html/rfc10042#section-2.3.3))
- `mlkem768nistp256-sha256` ([RFC 10042 section 2.3.1](https://www.rfc-editor.org/rfc/rfc10042.html#section-2.3.1))
- `mlkem1024nistp384-sha384` ([RFC 10042 section 2.3.2](https://www.rfc-editor.org/rfc/rfc10042.html#section-2.3.2))
- `mlkem768-sha256` ([pure ML-KEM draft](https://datatracker.ietf.org/doc/html/draft-harrison-sshm-mlkem-02)) — **opt-in**
- `mlkem1024-sha384` ([pure ML-KEM draft](https://datatracker.ietf.org/doc/html/draft-harrison-sshm-mlkem-02)) — **opt-in**
- `sntrup761x25519-sha512` ([RFC 9941](https://www.rfc-editor.org/rfc/rfc9941.html))
- `sntrup761x25519-sha512@openssh.com` (the interoperable OpenSSH alias from RFC 9941)
- `curve25519-sha256` ([RFC 8731](https://tools.ietf.org/html/rfc8731))
- `ecdh-sha2-nistp521` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
- `ecdh-sha2-nistp384` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
- `ecdh-sha2-nistp256` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
- `diffie-hellman-group18-sha512` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
- `diffie-hellman-group16-sha512` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
- `diffie-hellman-group14-sha256` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
- `diffie-hellman-group-exchange-sha256` ([RFC 4419](https://tools.ietf.org/html/rfc4419))
- `diffie-hellman-group14-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1)) — **legacy opt-in**
- `diffie-hellman-group-exchange-sha1` ([RFC 4419](https://tools.ietf.org/html/rfc4419)) — **legacy opt-in**
- `diffie-hellman-group1-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1)) — **legacy opt-in**

ML-KEM and SNTRUP761 key exchanges are available on Android and JVM 17 without
installing additional cryptographic providers. Pure ML-KEM methods require
explicit opt-in through `kexAlgorithms`.

The default key exchange list also advertises `kex-strict-c-v00@openssh.com`
(strict key exchange) and `ext-info-c` (extension negotiation). These are
protocol negotiation markers, not cryptographic key exchange algorithms.

## Encryption

- `chacha20-poly1305@openssh.com` ([draft-ietf-sshm-chacha20-poly1305](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-chacha20-poly1305))
- `aes256-gcm@openssh.com` ([draft-miller-sshm-aes-gcm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm))
- `aes128-gcm@openssh.com` ([draft-miller-sshm-aes-gcm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm))
- `aes256-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
- `aes128-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
- `aes256-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3)) — **legacy opt-in**
- `aes128-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3)) — **legacy opt-in**
- `3des-cbc` ([RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.3)) — **legacy opt-in**

## MACs

Only `hmac-sha2-256-etm@openssh.com` and `hmac-sha2-512-etm@openssh.com` are
offered by default. The AEAD ciphers (ChaCha20-Poly1305 and AES-GCM) provide
their own authentication and do not use a separate packet MAC.

- `hmac-sha2-512-etm@openssh.com` ([OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/60b909fb110f77c1ffd15cceb5d09b8e3f79b27e/PROTOCOL#L50))
- `hmac-sha2-256-etm@openssh.com` ([OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/60b909fb110f77c1ffd15cceb5d09b8e3f79b27e/PROTOCOL#L50))
- `hmac-sha1-etm@openssh.com` ([OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/60b909fb110f77c1ffd15cceb5d09b8e3f79b27e/PROTOCOL#L50)) — **legacy opt-in**
- `hmac-sha2-512` ([RFC 4868](https://tools.ietf.org/html/rfc4868)) — **legacy opt-in**
- `hmac-sha2-256` ([RFC 4868](https://tools.ietf.org/html/rfc4868)) — **legacy opt-in**
- `hmac-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253)) — **legacy opt-in**

## Compression

- `none` — default; no compression
- `zlib@openssh.com` — compression activated after successful authentication
- `zlib` ([RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.2)) — compression activated with the negotiated keys

Set `SshClientConfig.enableCompression = true` to offer
`zlib@openssh.com,zlib,none`, in that preference order. Compression is disabled
by default.
