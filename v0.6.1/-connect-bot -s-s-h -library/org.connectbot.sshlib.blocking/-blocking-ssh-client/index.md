//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)

# BlockingSshClient

[jvm]\
class [BlockingSshClient](index.md)

Blocking wrapper for SshClient for Java compatibility.

This class wraps the async [SshClient](../../org.connectbot.sshlib/-ssh-client/index.md) with blocking calls using runBlocking. For Kotlin code, prefer using [SshClient](../../org.connectbot.sshlib/-ssh-client/index.md) directly with coroutines.

Usage from Java:

```java
BlockingSshClient client = new BlockingSshClient("example.com", 22, myHostKeyVerifier);
try {
    client.connect();
    client.authenticatePassword("user", "password");
    SshSession session = client.openSession();
    // ...
    session.close();
    client.disconnect();
} catch (SshException e) {
    // handle connection or auth failure
}
```

With custom transport:

```java
BlockingSshClient client = new BlockingSshClient(myTransportFactory, myHostKeyVerifier);
```

## Constructors

| | |
|---|---|
| [BlockingSshClient](-blocking-ssh-client.md) | [jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>constructor(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;)<br>Create a blocking SSH client for TCP connection.<br>constructor(config: [SshClientConfig](../../org.connectbot.sshlib/-ssh-client-config/index.md))<br>Create a blocking SSH client from configuration.<br>constructor(transportFactory: [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md), hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;)<br>Create a blocking SSH client with custom transport factory. |

## Properties

| Name | Summary |
|---|---|
| [disconnectedFlow](disconnected-flow.md) | [jvm]<br>val [disconnectedFlow](disconnected-flow.md): SharedFlow&lt;[Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)?&gt;<br>Emits when the connection drops unexpectedly. |
| [isAuthenticated](is-authenticated.md) | [jvm]<br>val [isAuthenticated](is-authenticated.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Check if connected and authenticated. |

## Functions

| Name | Summary |
|---|---|
| [authenticate](authenticate.md) | [jvm]<br>fun [authenticate](authenticate.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), handler: [AuthHandler](../../org.connectbot.sshlib/-auth-handler/index.md))<br>Authenticate using the strategy-based [AuthHandler](../../org.connectbot.sshlib/-auth-handler/index.md) flow. |
| [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md) | [jvm]<br>fun [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), callback: [KeyboardInteractiveCallback](../../org.connectbot.sshlib/-keyboard-interactive-callback/index.md))<br>Authenticate using keyboard-interactive authentication (RFC 4256). |
| [authenticatePassword](authenticate-password.md) | [jvm]<br>fun [authenticatePassword](authenticate-password.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html))<br>Authenticate using password authentication. |
| [authenticatePublicKey](authenticate-public-key.md) | [jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null)<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null)<br>Authenticate using public key authentication (RFC 4252 §7). |
| [connect](connect.md) | [jvm]<br>fun [connect](connect.md)()<br>Connect to the SSH server and perform key exchange. |
| [disconnect](disconnect.md) | [jvm]<br>fun [disconnect](disconnect.md)()<br>Disconnect from the SSH server. |
| [dynamicPortForward](dynamic-port-forward.md) | [jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>fun [dynamicPortForward](dynamic-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), authenticator: [Socks5Authenticator](../../org.connectbot.sshlib/-socks5-authenticator/index.md)? = null): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?<br>Start dynamic (SOCKS5) port forwarding.<br>[jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>fun [dynamicPortForward](dynamic-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), authenticator: [Socks5Authenticator](../../org.connectbot.sshlib/-socks5-authenticator/index.md)? = null): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?<br>Start dynamic (SOCKS5) port forwarding bound to localhost. |
| [enableAgentForwarding](enable-agent-forwarding.md) | [jvm]<br>fun [enableAgentForwarding](enable-agent-forwarding.md)(provider: [AgentProvider](../../org.connectbot.sshlib/-agent-provider/index.md))<br>Enable SSH agent forwarding with the provided agent. |
| [forwardStream](forward-stream.md) | [jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>fun [forwardStream](forward-stream.md)(readChannel: ByteReadChannel, writeChannel: ByteWriteChannel, remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;127.0.0.1&quot;, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [StreamForwarder](../../org.connectbot.sshlib/-stream-forwarder/index.md)?<br>Forward Ktor byte channels through an SSH direct-tcpip channel. |
| [localPortForward](local-port-forward.md) | [jvm]<br>fun [localPortForward](local-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?<br>Start local port forwarding.<br>[jvm]<br>fun [localPortForward](local-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?<br>Start local port forwarding bound to localhost. |
| [openDirectTcpipTransport](open-direct-tcpip-transport.md) | [jvm]<br>@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)<br>fun [openDirectTcpipTransport](open-direct-tcpip-transport.md)(remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;127.0.0.1&quot;, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md)?<br>Create a [org.connectbot.sshlib.transport.TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md) that tunnels through this SSH connection. |
| [openSession](open-session.md) | [jvm]<br>fun [openSession](open-session.md)(): [SshSession](../../org.connectbot.sshlib/-ssh-session/index.md)?<br>Open a session channel (RFC 4254 section 6.1). |
| [openSftp](open-sftp.md) | [jvm]<br>fun [openSftp](open-sftp.md)(): [SftpClient](../../org.connectbot.sshlib/-sftp-client/index.md)<br>Open an SFTP session for file transfer (blocking wrapper). |
| [ping](ping.md) | [jvm]<br>fun [ping](ping.md)(): [PingResult](../../org.connectbot.sshlib/-ping-result/index.md)<br>Send an SSH ping to the server and return the result. |
| [remotePortForward](remote-port-forward.md) | [jvm]<br>fun [remotePortForward](remote-port-forward.md)(remoteBindAddress: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remoteBindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), localHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), localPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?<br>Start remote port forwarding. |