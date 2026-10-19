//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[localPortForward](local-port-forward.md)

# localPortForward

[jvm]\
suspend fun [localPortForward](local-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../-port-forwarder/index.md)?

Start local port forwarding (RFC 4254 section 7.2).

Listens on [bindAddress](local-port-forward.md) locally and forwards each connection through SSH to [remoteHost](local-port-forward.md):[remotePort](local-port-forward.md) on the remote side.

#### Return

PortForwarder handle, or null if not authenticated

#### Parameters

jvm

| | |
|---|---|
| bindAddress | Local address to bind |
| remoteHost | Remote host to connect to through SSH |
| remotePort | Remote port to connect to through SSH |

[jvm]\
suspend fun [localPortForward](local-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../-port-forwarder/index.md)?

Start local port forwarding bound to localhost.

#### Return

PortForwarder handle, or null if not authenticated

#### Parameters

jvm

| | |
|---|---|
| bindPort | Local port to bind (0 for automatic) |
| remoteHost | Remote host to connect to through SSH |
| remotePort | Remote port to connect to through SSH |