//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[ConnectResult](index.md)

# ConnectResult

sealed interface [ConnectResult](index.md)

Result of [SshClient.connect](../-ssh-client/connect.md).

#### Inheritors

| |
|---|
| [Success](-success/index.md) |
| [HostKeyRejected](-host-key-rejected/index.md) |
| [AlgorithmMismatch](-algorithm-mismatch/index.md) |
| [TransportError](-transport-error/index.md) |
| [ProtocolError](-protocol-error/index.md) |

## Types

| Name | Summary |
|---|---|
| [AlgorithmMismatch](-algorithm-mismatch/index.md) | [jvm]<br>data class [AlgorithmMismatch](-algorithm-mismatch/index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) : [ConnectResult](index.md) |
| [HostKeyRejected](-host-key-rejected/index.md) | [jvm]<br>data class [HostKeyRejected](-host-key-rejected/index.md)(val key: [PublicKey](../-public-key/index.md)) : [ConnectResult](index.md) |
| [ProtocolError](-protocol-error/index.md) | [jvm]<br>data class [ProtocolError](-protocol-error/index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [ConnectResult](index.md) |
| [Success](-success/index.md) | [jvm]<br>data object [Success](-success/index.md) : [ConnectResult](index.md) |
| [TransportError](-transport-error/index.md) | [jvm]<br>data class [TransportError](-transport-error/index.md)(val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)) : [ConnectResult](index.md) |