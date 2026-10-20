//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthPublicKey](index.md)

# AuthPublicKey

data class [AuthPublicKey](index.md)(val algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))

An SSH public key for authentication probing.

#### Parameters

jvm

| | |
|---|---|
| algorithmName | SSH algorithm name (e.g., &quot;ssh-ed25519&quot;, &quot;rsa-sha2-256&quot;) |
| publicKeyBlob | Wire-format public key blob |

## Constructors

| | |
|---|---|
| [AuthPublicKey](-auth-public-key.md) | [jvm]<br>constructor(algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [algorithmName](algorithm-name.md) | [jvm]<br>val [algorithmName](algorithm-name.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [publicKeyBlob](public-key-blob.md) | [jvm]<br>val [publicKeyBlob](public-key-blob.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html) |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [jvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [hashCode](hash-code.md) | [jvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |