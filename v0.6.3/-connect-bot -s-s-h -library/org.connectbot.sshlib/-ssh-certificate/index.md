//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshCertificate](index.md)

# SshCertificate

[jvm]\
class [SshCertificate](index.md)

An OpenSSH v01 certificate. Decoding checks structure, but does not establish CA trust.

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |
| [Type](-type/index.md) | [jvm]<br>enum [Type](-type/index.md) : [Enum](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-enum/index.html)&lt;[SshCertificate.Type](-type/index.md)&gt; |

## Properties

| Name | Summary |
|---|---|
| [algorithmName](algorithm-name.md) | [jvm]<br>val [algorithmName](algorithm-name.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [criticalOptions](critical-options.md) | [jvm]<br>val [criticalOptions](critical-options.md): [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt; |
| [encoded](encoded.md) | [jvm]<br>val [encoded](encoded.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Original SSH certificate wire blob. Returned byte arrays are independent copies. |
| [extensions](extensions.md) | [jvm]<br>val [extensions](extensions.md): [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt; |
| [keyId](key-id.md) | [jvm]<br>val [keyId](key-id.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [principals](principals.md) | [jvm]<br>val [principals](principals.md): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt; |
| [publicKey](public-key.md) | [jvm]<br>val [publicKey](public-key.md): [PublicKey](../-public-key/index.md)<br>Certified raw public key, including the application identifier for security keys. |
| [serial](serial.md) | [jvm]<br>val [serial](serial.md): [ULong](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-u-long/index.html)<br>CA-assigned unsigned serial number; zero means unassigned. |
| [signatureKey](signature-key.md) | [jvm]<br>val [signatureKey](signature-key.md): [PublicKey](../-public-key/index.md)<br>Raw public key of the issuing certificate authority. |
| [type](type.md) | [jvm]<br>val [type](type.md): [SshCertificate.Type](-type/index.md) |
| [validAfter](valid-after.md) | [jvm]<br>val [validAfter](valid-after.md): [ULong](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-u-long/index.html)<br>Inclusive validity start, in seconds since the Unix epoch. |
| [validBefore](valid-before.md) | [jvm]<br>val [validBefore](valid-before.md): [ULong](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-u-long/index.html)<br>Exclusive validity end, in seconds since the Unix epoch; ULong.MAX_VALUE means no expiry. |

## Functions

| Name | Summary |
|---|---|
| [toAuthPublicKey](to-auth-public-key.md) | [jvm]<br>fun [toAuthPublicKey](to-auth-public-key.md)(): [AuthPublicKey](../-auth-public-key/index.md)<br>Return this user certificate for an external signer, including security-key signers. |