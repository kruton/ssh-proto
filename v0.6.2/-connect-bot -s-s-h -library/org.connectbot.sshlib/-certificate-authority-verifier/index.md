//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[CertificateAuthorityVerifier](index.md)

# CertificateAuthorityVerifier

[jvm]\
class [CertificateAuthorityVerifier](index.md)@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)constructor(hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), trustedAuthorities: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;, revocations: [SshKeyRevocationList](../-ssh-key-revocation-list/index.md)? = null) : [HostKeyVerifier](../-host-key-verifier/index.md)

Trust host certificates issued by one of trustedAuthorities for hostname. The hostname is the logical destination name, including with a custom transport, without brackets or a port. CA keys and optional revocations are snapshots.

## Constructors

| | |
|---|---|
| [CertificateAuthorityVerifier](-certificate-authority-verifier.md) | [jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>constructor(hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), trustedAuthorities: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;, revocations: [SshKeyRevocationList](../-ssh-key-revocation-list/index.md)? = null) |

## Functions

| Name | Summary |
|---|---|
| [addKeys](../-host-key-verifier/add-keys.md) | [jvm]<br>open suspend fun [addKeys](../-host-key-verifier/add-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;)<br>Persist the supported keys advertised by an authenticated server after every requested proof of private-key possession has been verified. Runs outside packet routing. Read-only verifiers may keep the default implementation. |
| [removeKeys](../-host-key-verifier/remove-keys.md) | [jvm]<br>open suspend fun [removeKeys](../-host-key-verifier/remove-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;)<br>Retire the authenticated key when omitted from the advertisement, after [addKeys](../-host-key-verifier/add-keys.md) returns successfully. Other stored keys are not enumerated or removed. |
| [verify](verify.md) | [jvm]<br>open suspend override fun [verify](verify.md)(key: [PublicKey](../-public-key/index.md)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Verify the server's host key. |