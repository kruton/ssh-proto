//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[ConnectionInfo](index.md)

# ConnectionInfo

[jvm]\
data class [ConnectionInfo](index.md)(val kexAlgorithm: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val serverHostKeyAlgorithm: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val encryptionAlgorithmC2S: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val encryptionAlgorithmS2C: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val macAlgorithmC2S: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?, val macAlgorithmS2C: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?)

Negotiated algorithm details for an established SSH connection.

Available via [SshClient.connectionInfo](../-ssh-client/connection-info.md) after a successful [SshClient.connect](../-ssh-client/connect.md).

## Constructors

| | |
|---|---|
| [ConnectionInfo](-connection-info.md) | [jvm]<br>constructor(kexAlgorithm: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), serverHostKeyAlgorithm: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), encryptionAlgorithmC2S: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), encryptionAlgorithmS2C: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), macAlgorithmC2S: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?, macAlgorithmS2C: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?) |

## Properties

| Name | Summary |
|---|---|
| [encryptionAlgorithmC2S](encryption-algorithm-c2-s.md) | [jvm]<br>val [encryptionAlgorithmC2S](encryption-algorithm-c2-s.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [encryptionAlgorithmS2C](encryption-algorithm-s2-c.md) | [jvm]<br>val [encryptionAlgorithmS2C](encryption-algorithm-s2-c.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [isPostQuantumSecure](is-post-quantum-secure.md) | [jvm]<br>val [isPostQuantumSecure](is-post-quantum-secure.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>True if the key exchange algorithm is post-quantum secure. |
| [kexAlgorithm](kex-algorithm.md) | [jvm]<br>val [kexAlgorithm](kex-algorithm.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [macAlgorithmC2S](mac-algorithm-c2-s.md) | [jvm]<br>val [macAlgorithmC2S](mac-algorithm-c2-s.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?<br>Null when the cipher is AEAD (no separate MAC needed). |
| [macAlgorithmS2C](mac-algorithm-s2-c.md) | [jvm]<br>val [macAlgorithmS2C](mac-algorithm-s2-c.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?<br>Null when the cipher is AEAD (no separate MAC needed). |
| [serverHostKeyAlgorithm](server-host-key-algorithm.md) | [jvm]<br>val [serverHostKeyAlgorithm](server-host-key-algorithm.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |