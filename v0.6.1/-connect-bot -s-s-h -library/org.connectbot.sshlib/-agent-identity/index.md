//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentIdentity](index.md)

# AgentIdentity

data class [AgentIdentity](index.md)(val publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val comment: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val destinationConstraints: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[DestinationConstraint](../-destination-constraint/index.md)&gt;? = null)

A public key identity available in the agent.

#### Parameters

jvm

| | |
|---|---|
| publicKeyBlob | Wire-format public key blob |
| comment | Human-readable comment describing the key |
| destinationConstraints | Optional per-hop destination constraints; null means unconstrained |

## Constructors

| | |
|---|---|
| [AgentIdentity](-agent-identity.md) | [jvm]<br>constructor(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), comment: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), destinationConstraints: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[DestinationConstraint](../-destination-constraint/index.md)&gt;? = null) |

## Properties

| Name | Summary |
|---|---|
| [comment](comment.md) | [jvm]<br>val [comment](comment.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [destinationConstraints](destination-constraints.md) | [jvm]<br>val [destinationConstraints](destination-constraints.md): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[DestinationConstraint](../-destination-constraint/index.md)&gt;? |
| [publicKeyBlob](public-key-blob.md) | [jvm]<br>val [publicKeyBlob](public-key-blob.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html) |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [jvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [hashCode](hash-code.md) | [jvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |