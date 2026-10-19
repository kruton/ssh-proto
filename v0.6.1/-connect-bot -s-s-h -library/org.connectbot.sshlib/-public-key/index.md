//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[PublicKey](index.md)

# PublicKey

data class [PublicKey](index.md)(val type: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val encoded: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))

A generic public key representation.

#### Parameters

jvm

| | |
|---|---|
| type | The key type (e.g., &quot;ssh-rsa&quot;, &quot;ecdsa-sha2-nistp256&quot;). |
| encoded | The raw key data (wire format). |

## Constructors

| | |
|---|---|
| [PublicKey](-public-key.md) | [jvm]<br>constructor(type: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), encoded: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [encoded](encoded.md) | [jvm]<br>val [encoded](encoded.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html) |
| [type](type.md) | [jvm]<br>val [type](type.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [jvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [hashCode](hash-code.md) | [jvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |