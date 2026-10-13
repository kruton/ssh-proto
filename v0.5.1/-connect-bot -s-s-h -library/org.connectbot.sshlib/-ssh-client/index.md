//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)

# SshClient

[jvm]\
class [SshClient](index.md)

High-level async SSH client API.

This is the main entry point for establishing SSH connections. All methods are suspend functions for use with Kotlin coroutines.

Usage with TCP (default):

```kotlin
val client = SshClient("example.com", hostKeyVerifier = myVerifier)
if (client.connect() is ConnectResult.Success) {
    if (client.authenticatePassword("user", "password") is AuthResult.Success) {
        val session = client.openSession()
        session?.requestPty()
        session?.requestShell()
        // read/write
        session?.close()
    }
    client.disconnect()
}
```

Usage with custom transport:

```kotlin
val config = SshClientConfig {
    transportFactory = MyCustomTransportFactory()
}
val client = SshClient(config)
client.connect()
// ...
```

For blocking Java compatibility, use [org.connectbot.sshlib.blocking.BlockingSshClient](../../org.connectbot.sshlib.blocking/-blocking-ssh-client/index.md).

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [connectionInfo](connection-info.md) | [jvm]<br>val [connectionInfo](connection-info.md): [ConnectionInfo](../-connection-info/index.md)?<br>Negotiated algorithm details for the current connection. |
| [disconnectedFlow](disconnected-flow.md) | [jvm]<br>val [disconnectedFlow](disconnected-flow.md): SharedFlow&lt;[Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)?&gt;<br>Emits when the connection drops unexpectedly. |
| [isAuthenticated](is-authenticated.md) | [jvm]<br>val [isAuthenticated](is-authenticated.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Check if connected and authenticated. |

## Functions

| Name | Summary |
|---|---|
| [authenticate](authenticate.md) | [jvm]<br>suspend fun [authenticate](authenticate.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), handler: [AuthHandler](../-auth-handler/index.md)): [AuthResult](../-auth-result/index.md)<br>Authenticate using the strategy-based [AuthHandler](../-auth-handler/index.md) flow. |
| [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md) | [jvm]<br>suspend fun [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), callback: [KeyboardInteractiveCallback](../-keyboard-interactive-callback/index.md)): [AuthResult](../-auth-result/index.md)<br>Authenticate using keyboard-interactive authentication (RFC 4256). |
| [authenticatePassword](authenticate-password.md) | [jvm]<br>suspend fun [authenticatePassword](authenticate-password.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AuthResult](../-auth-result/index.md)<br>Authenticate using password authentication. |
| [authenticatePublicKey](authenticate-public-key.md) | [jvm]<br>suspend fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [AuthResult](../-auth-result/index.md)<br>suspend fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [AuthResult](../-auth-result/index.md)<br>Authenticate using public key authentication (RFC 4252 §7). |
| [connect](connect.md) | [jvm]<br>suspend fun [connect](connect.md)(): [ConnectResult](../-connect-result/index.md)<br>Connect to the SSH server and perform key exchange. |
| [disconnect](disconnect.md) | [jvm]<br>suspend fun [disconnect](disconnect.md)()<br>Disconnect from the SSH server. |
| [dynamicPortForward](dynamic-port-forward.md) | [jvm]<br>suspend fun [dynamicPortForward](dynamic-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), authenticator: [Socks5Authenticator](../-socks5-authenticator/index.md)? = null): [PortForwarder](../-port-forwarder/index.md)?<br>Start dynamic (SOCKS5) port forwarding.<br>[jvm]<br>suspend fun [dynamicPortForward](dynamic-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), authenticator: [Socks5Authenticator](../-socks5-authenticator/index.md)? = null): [PortForwarder](../-port-forwarder/index.md)?<br>Start dynamic (SOCKS5) port forwarding bound to localhost. |
| [enableAgentForwarding](enable-agent-forwarding.md) | [jvm]<br>fun [enableAgentForwarding](enable-agent-forwarding.md)(provider: [AgentProvider](../-agent-provider/index.md))<br>Enable SSH agent forwarding with the provided agent. |
| [forwardStream](forward-stream.md) | [jvm]<br>suspend fun [forwardStream](forward-stream.md)(readChannel: ByteReadChannel, writeChannel: ByteWriteChannel, remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = LOCALHOST, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [StreamForwarder](../-stream-forwarder/index.md)?<br>Forward a pair of streams through an SSH direct-tcpip channel. |
| [isPrivateKeyEncrypted](is-private-key-encrypted.md) | [jvm]<br>fun [isPrivateKeyEncrypted](is-private-key-encrypted.md)(privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>fun [isPrivateKeyEncrypted](is-private-key-encrypted.md)(privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Check if the provided private key data is encrypted and requires a passphrase. |
| [localPortForward](local-port-forward.md) | [jvm]<br>suspend fun [localPortForward](local-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../-port-forwarder/index.md)?<br>Start local port forwarding (RFC 4254 section 7.2).<br>[jvm]<br>suspend fun [localPortForward](local-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../-port-forwarder/index.md)?<br>Start local port forwarding bound to localhost. |
| [openDirectTcpipTransport](open-direct-tcpip-transport.md) | [jvm]<br>fun [openDirectTcpipTransport](open-direct-tcpip-transport.md)(remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = LOCALHOST, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md)?<br>Create a [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md) that tunnels through this SSH connection. |
| [openSession](open-session.md) | [jvm]<br>suspend fun [openSession](open-session.md)(): [SshSession](../-ssh-session/index.md)?<br>Open a session channel (RFC 4254 section 6.1). |
| [openSftp](open-sftp.md) | [jvm]<br>suspend fun [openSftp](open-sftp.md)(): [SftpResult](../-sftp-result/index.md)&lt;[SftpClient](../-sftp-client/index.md)&gt;<br>Open an SFTP session for file transfer. |
| [ping](ping.md) | [jvm]<br>suspend fun [ping](ping.md)(): [PingResult](../-ping-result/index.md)<br>Send an SSH ping to the server and return the round-trip time. |
| [remotePortForward](remote-port-forward.md) | [jvm]<br>suspend fun [remotePortForward](remote-port-forward.md)(remoteBindAddress: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remoteBindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), localHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), localPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../-port-forwarder/index.md)?<br>Start remote port forwarding (RFC 4254 section 7.1). |