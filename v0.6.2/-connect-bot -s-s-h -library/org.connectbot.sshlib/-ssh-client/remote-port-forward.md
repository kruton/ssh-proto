//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[remotePortForward](remote-port-forward.md)

# remotePortForward

[jvm]\
suspend fun [remotePortForward](remote-port-forward.md)(remoteBindAddress: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remoteBindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), localHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), localPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../-port-forwarder/index.md)?

Start remote port forwarding (RFC 4254 section 7.1).

Asks the SSH server to listen on [remoteBindAddress](remote-port-forward.md):[remoteBindPort](remote-port-forward.md) and forwards each connection back to [localHost](remote-port-forward.md):[localPort](remote-port-forward.md) on this machine.

#### Return

PortForwarder handle, or null if the server rejected the request

#### Parameters

jvm

| | |
|---|---|
| remoteBindAddress | Address for the server to bind |
| remoteBindPort | Port for the server to bind (0 for automatic) |
| localHost | Local host to forward to |
| localPort | Local port to forward to |