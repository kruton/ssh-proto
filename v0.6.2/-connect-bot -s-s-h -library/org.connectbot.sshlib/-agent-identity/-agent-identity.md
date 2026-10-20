//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentIdentity](index.md)/[AgentIdentity](-agent-identity.md)

# AgentIdentity

[jvm]\
constructor(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), comment: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), destinationConstraints: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[DestinationConstraint](../-destination-constraint/index.md)&gt;? = null)

#### Parameters

jvm

| | |
|---|---|
| publicKeyBlob | Wire-format public key blob |
| comment | Human-readable comment describing the key |
| destinationConstraints | Optional per-hop destination constraints; null means unconstrained |