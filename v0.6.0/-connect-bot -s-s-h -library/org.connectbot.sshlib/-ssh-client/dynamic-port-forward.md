//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[dynamicPortForward](dynamic-port-forward.md)

# dynamicPortForward

[jvm]\
suspend fun [dynamicPortForward](dynamic-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), authenticator: [Socks5Authenticator](../-socks5-authenticator/index.md)? = null): [PortForwarder](../-port-forwarder/index.md)?

Start dynamic (SOCKS5) port forwarding.

Listens on [bindAddress](dynamic-port-forward.md) locally as a SOCKS5 proxy. Each SOCKS5 CONNECT request opens a direct-tcpip channel through SSH to the requested destination.

#### Return

PortForwarder handle, or null if not authenticated

#### Parameters

jvm

| | |
|---|---|
| bindAddress | Local address to bind the SOCKS5 proxy |
| authenticator | Optional SOCKS5 username/password authenticator |

[jvm]\
suspend fun [dynamicPortForward](dynamic-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), authenticator: [Socks5Authenticator](../-socks5-authenticator/index.md)? = null): [PortForwarder](../-port-forwarder/index.md)?

Start dynamic (SOCKS5) port forwarding bound to localhost.

#### Return

PortForwarder handle, or null if not authenticated

#### Parameters

jvm

| | |
|---|---|
| bindPort | Local port to bind (0 for automatic) |
| authenticator | Optional SOCKS5 username/password authenticator |