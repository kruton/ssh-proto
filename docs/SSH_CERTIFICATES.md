# OpenSSH Certificate Authentication

OpenSSH v01 user and host certificates are supported for Ed25519, RSA, and
ECDSA (P-256/P-384/P-521). SK-Ed25519 and SK-ECDSA user certificates work through
`AuthHandler` with an application-provided signer. Certificates are issued outside
this library, for example using `ssh-keygen -s`.

## User Certificates

Load a user certificate and authenticate with its matching private key:

```kotlin
val certificate = SshCertificate.decode(File("id_ed25519-cert.pub").readText())
val result = client.authenticatePublicKey(
    username = "user",
    privateKeyData = File("id_ed25519").readBytes(),
    certificate = certificate,
    passphrase = null,
)
check(result is AuthResult.Success)
```

The blocking client provides the same overloads. Java callers supply the nullable
passphrase argument explicitly for certificate authentication. The client checks
that the private key matches the certified public key. The server enforces user-certificate
validity, authorized principals, and restrictions; principals may represent roles
rather than the login username.

For external signing, return `certificate.toAuthPublicKey()` from
`AuthHandler.onPublicKeysNeeded()`. The signature callback receives the selected
certificate algorithm and the complete authentication payload. Local callbacks
can call `SshSigning.sign(key.algorithmName, privateKeyData, passphrase, dataToSign)`.
Security-key callbacks decode `certificate.publicKey.encoded` with
`SkPublicKeyDecoder.decode`, request an assertion for `SHA-256(dataToSign)` using
the decoded application, and return `SkSignatureBlob.pack(...)` with the underlying
`SkAlgorithm`. Device access, PINs, and CTAP remain the application's responsibility.

## Host Certificates

For host certificates, trust the issuing CA in `known_hosts`:

```text
@cert-authority *.example.com ssh-ed25519 AAAA...host-ca-public-key...
```

Then explicitly enable host certificate algorithms:

```kotlin
val config = SshClientConfig {
    host = "server.example.com"
    hostKeyVerifier = KnownHostsVerifier(File("known_hosts"), host)
    enableCertificateHostKeys() // Equivalent to enableCertificateHostKeys(true).
}
```

The builder prepends certificate counterparts of the final `hostKeyAlgorithms`
list during `build()`, without changing that list on the builder. Assignment order
is irrelevant, repeated calls do not duplicate algorithms, and the last boolean
setting wins. Raw algorithms remain available as fallback; `false` stops automatic
additions while retaining explicitly configured certificate algorithms. Certificate
algorithms are off by default.

Applications can instead configure CA trust in memory. Supply the logical server
hostname without a port, including when using a custom transport:

```kotlin
val verifier = CertificateAuthorityVerifier(
    hostname = "server.example.com",
    trustedAuthorities = listOf(PublicKey("ssh-ed25519", caPublicKeyWireBytes)),
)
```

Both built-in verifiers check the CA signature, host certificate type, validity,
hostname principal, critical options, and configured revocations. CA signatures
must use Ed25519, ECDSA, or RSA/SHA-2. `KnownHostsVerifier` supports `@revoked`,
negated host patterns, and `[hostname]:port` entries. Unknown host critical options
are rejected; unknown noncritical extensions are ignored. Certificate-authenticated
connections do not learn raw host keys through the host-key update extension.
Custom `HostKeyVerifier` implementations receive the full certificate in `PublicKey`;
`SshCertificate.decode` alone does not establish trust.

## Revocation

Load an OpenSSH KRL produced by `ssh-keygen -k` through a trusted channel:

```kotlin
val revocations = SshKeyRevocationList.decode(File("revoked.krl").readBytes())
val verifier = CertificateAuthorityVerifier("server.example.com", trustedCas, revocations)
// Or: KnownHostsVerifier(File("known_hosts"), "server.example.com", 22, revocations)
val revoked = revocations.isRevoked(PublicKey(certificate.algorithmName, certificate.encoded))
```

A certificate query checks its serial/key ID, certified key, and issuing CA.
Passing a raw `PublicKey` checks only that key's revocation.
KRLs support serial lists/ranges/bitmaps, key IDs, explicit keys, SHA-1/SHA-256
fingerprints, and CA revocation. Malformed or unsupported lists throw `SshException`;
they are never treated as empty. KRL signature sections are unsupported.
Lists are immutable snapshots: applications own trusted distribution,
file loading, and refresh. The server remains responsible for user revocation policy.
