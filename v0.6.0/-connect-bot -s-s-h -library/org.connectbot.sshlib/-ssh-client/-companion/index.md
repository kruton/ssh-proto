//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClient](../index.md)/[Companion](index.md)

# Companion

[jvm]\
object [Companion](index.md)

## Functions

| Name | Summary |
|---|---|
| [invoke](invoke.md) | [jvm]<br>operator fun [invoke](invoke.md)(config: [SshClientConfig](../../-ssh-client-config/index.md)): [SshClient](../index.md)<br>Create an SshClient from a configuration.<br>[jvm]<br>operator fun [invoke](invoke.md)(transportFactory: [TransportFactory](../../../org.connectbot.sshlib.transport/-transport-factory/index.md), hostKeyVerifier: [HostKeyVerifier](../../-host-key-verifier/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;): [SshClient](../index.md)<br>Create an SshClient with a custom transport factory.<br>[jvm]<br>operator fun [invoke](invoke.md)(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), hostKeyVerifier: [HostKeyVerifier](../../-host-key-verifier/index.md), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;): [SshClient](../index.md)<br>Create an SshClient for TCP connection to the specified host. |