//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkPublicKey](index.md)

# SkPublicKey

[jvm]\
data class [SkPublicKey](index.md)(val algorithm: [SkAlgorithm](../-sk-algorithm/index.md), val rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html))

Decoded SK public key.

## Constructors

| | |
|---|---|
| [SkPublicKey](-sk-public-key.md) | [jvm]<br>constructor(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [algorithm](algorithm.md) | [jvm]<br>val [algorithm](algorithm.md): [SkAlgorithm](../-sk-algorithm/index.md)<br>Which SK algorithm this key uses. |
| [application](application.md) | [jvm]<br>val [application](application.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>The relying-party identifier the key was bound to (typically `"ssh:"` for keys generated with `ssh-keygen -t ed25519-sk`). |
| [rawKey](raw-key.md) | [jvm]<br>val [rawKey](raw-key.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Algorithm-specific raw public key bytes. For [SkAlgorithm.ED25519](../-sk-algorithm/-e-d25519/index.md) this is the 32-byte raw Ed25519 public key. For [SkAlgorithm.ECDSA_P256](../-sk-algorithm/-e-c-d-s-a_-p256/index.md) this is the uncompressed SEC1 point (`0x04 || X(32) || Y(32)`, 65 bytes). |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [jvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [hashCode](hash-code.md) | [jvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |