//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClientConfig](index.md)

# SshClientConfig

[jvm]\
class [SshClientConfig](index.md)

Configuration for SSH client connections.

Use the builder DSL to create a configuration:

```kotlin
// Simple TCP connection (uses KtorTcpTransport by default)
val config = SshClientConfig {
    host = "example.com"
    port = 22
    clientVersion = "SSH-2.0-MyClient_1.0"
}

// Custom transport
val config = SshClientConfig {
    transportFactory = MyCustomTransportFactory()
    clientVersion = "SSH-2.0-MyClient_1.0"
}
```

## Types

| Name | Summary |
|---|---|
| [Builder](-builder/index.md) | [jvm]<br>class [Builder](-builder/index.md) |
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [autoDisconnectOnLastChannelClose](auto-disconnect-on-last-channel-close.md) | [jvm]<br>val [autoDisconnectOnLastChannelClose](auto-disconnect-on-last-channel-close.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [clientVersion](client-version.md) | [jvm]<br>val [clientVersion](client-version.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [encryptionAlgorithms](encryption-algorithms.md) | [jvm]<br>val [encryptionAlgorithms](encryption-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [environment](environment.md) | [jvm]<br>val [environment](environment.md): [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt; |
| [hostKeyAlgorithms](host-key-algorithms.md) | [jvm]<br>val [hostKeyAlgorithms](host-key-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [hostKeyVerifier](host-key-verifier.md) | [jvm]<br>val [hostKeyVerifier](host-key-verifier.md): [HostKeyVerifier](../-host-key-verifier/index.md) |
| [keepAliveIntervalMs](keep-alive-interval-ms.md) | [jvm]<br>val [keepAliveIntervalMs](keep-alive-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) |
| [kexAlgorithms](kex-algorithms.md) | [jvm]<br>val [kexAlgorithms](kex-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [macAlgorithms](mac-algorithms.md) | [jvm]<br>val [macAlgorithms](mac-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [obscureKeystrokeTimingIntervalMs](obscure-keystroke-timing-interval-ms.md) | [jvm]<br>val [obscureKeystrokeTimingIntervalMs](obscure-keystroke-timing-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) |
| [preferPasswordAuth](prefer-password-auth.md) | [jvm]<br>val [preferPasswordAuth](prefer-password-auth.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [rekeyBytesLimit](rekey-bytes-limit.md) | [jvm]<br>val [rekeyBytesLimit](rekey-bytes-limit.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) |
| [rekeyIntervalMs](rekey-interval-ms.md) | [jvm]<br>val [rekeyIntervalMs](rekey-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) |
| [sessionWindowSize](session-window-size.md) | [jvm]<br>val [sessionWindowSize](session-window-size.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [sftpWindowSize](sftp-window-size.md) | [jvm]<br>val [sftpWindowSize](sftp-window-size.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [transportFactory](transport-factory.md) | [jvm]<br>val [transportFactory](transport-factory.md): [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md) |