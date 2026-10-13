//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClient](../index.md)/[Companion](index.md)/[invoke](invoke.md)

# invoke

[jvm]\
operator fun [invoke](invoke.md)(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), hostKeyVerifier: [HostKeyVerifier](../../-host-key-verifier/index.md), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;): [SshClient](../index.md)

Create an SshClient for TCP connection to the specified host.

#### Parameters

jvm

| | |
|---|---|
| host | SSH server hostname |
| port | SSH server port (default 22) |
| clientVersion | Client version string for the SSH handshake |

[jvm]\
operator fun [invoke](invoke.md)(config: [SshClientConfig](../../-ssh-client-config/index.md)): [SshClient](../index.md)

Create an SshClient from a configuration.

[jvm]\
operator fun [invoke](invoke.md)(transportFactory: [TransportFactory](../../../org.connectbot.sshlib.transport/-transport-factory/index.md), hostKeyVerifier: [HostKeyVerifier](../../-host-key-verifier/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;): [SshClient](../index.md)

Create an SshClient with a custom transport factory.

#### Parameters

jvm

| | |
|---|---|
| transportFactory | Factory to create the transport |
| clientVersion | Client version string for the SSH handshake |