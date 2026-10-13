//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentKeySpec](index.md)

# AgentKeySpec

data class [AgentKeySpec](index.md)(val keyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val isCa: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html))

A host key specification used in destination constraints.

#### Parameters

jvm

| | |
|---|---|
| keyBlob | Wire-format public key blob |
| isCa | True if this is a CA key that signed the destination's host certificate |

## Constructors

| | |
|---|---|
| [AgentKeySpec](-agent-key-spec.md) | [jvm]<br>constructor(keyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), isCa: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [isCa](is-ca.md) | [jvm]<br>val [isCa](is-ca.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [keyBlob](key-blob.md) | [jvm]<br>val [keyBlob](key-blob.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html) |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [jvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [hashCode](hash-code.md) | [jvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |