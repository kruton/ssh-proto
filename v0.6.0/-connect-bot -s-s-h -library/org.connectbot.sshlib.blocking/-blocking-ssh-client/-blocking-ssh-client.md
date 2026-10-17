//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[BlockingSshClient](-blocking-ssh-client.md)

# BlockingSshClient

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

constructor(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;)

Create a blocking SSH client for TCP connection.

[jvm]\
constructor(config: [SshClientConfig](../../org.connectbot.sshlib/-ssh-client-config/index.md))

Create a blocking SSH client from configuration.

[jvm]\
constructor(transportFactory: [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md), hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;)

Create a blocking SSH client with custom transport factory.