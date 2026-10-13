//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentSigningContext](index.md)

# AgentSigningContext

[jvm]\
data class [AgentSigningContext](index.md)(val publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val flags: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), val sessionId: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val serverHostKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val isBound: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html))

Context for agent signing decisions.

Provides information to help the agent provider make informed security decisions about whether to approve a signing request from a remote server.

## Constructors

| | |
|---|---|
| [AgentSigningContext](-agent-signing-context.md) | [jvm]<br>constructor(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), flags: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), sessionId: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), serverHostKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), isBound: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [dataToSign](data-to-sign.md) | [jvm]<br>val [dataToSign](data-to-sign.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Data to be signed |
| [flags](flags.md) | [jvm]<br>val [flags](flags.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)<br>Signature flags (0 for default, or RSA_SHA2_256/512) |
| [isBound](is-bound.md) | [jvm]<br>val [isBound](is-bound.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Whether a trusted session binding is active |
| [publicKeyBlob](public-key-blob.md) | [jvm]<br>val [publicKeyBlob](public-key-blob.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Wire-format public key blob being requested |
| [serverHostKey](server-host-key.md) | [jvm]<br>val [serverHostKey](server-host-key.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Server's host key from key exchange |
| [sessionId](session-id.md) | [jvm]<br>val [sessionId](session-id.md): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Session ID from the SSH connection (for session binding) |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [jvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [hashCode](hash-code.md) | [jvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |