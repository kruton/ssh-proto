//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[openDirectTcpipTransport](open-direct-tcpip-transport.md)

# openDirectTcpipTransport

[jvm]\
fun [openDirectTcpipTransport](open-direct-tcpip-transport.md)(remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = LOCALHOST, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md)?

Create a [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md) that tunnels through this SSH connection.

Opens a direct-tcpip channel to [remoteHost](open-direct-tcpip-transport.md):[remotePort](open-direct-tcpip-transport.md) and wraps it as a [Transport](../../org.connectbot.sshlib.transport/-transport/index.md), allowing a second [SshClient](index.md) to connect through this connection without transiting the kernel network stack (jump host / ProxyJump pattern).

```kotlin
val jump = SshClient("jump.example.com", hostKeyVerifier = jumpVerifier)
jump.connect()
jump.authenticatePassword("user", "pass")

val targetConfig = SshClientConfig {
    transportFactory = jump.openDirectTcpipTransport("target.internal", 22)
    hostKeyVerifier = myVerifier
}
val target = SshClient(targetConfig)
target.connect()
```

#### Return

TransportFactory for use in [SshClientConfig](../-ssh-client-config/index.md), or null if not authenticated

#### Parameters

jvm

| | |
|---|---|
| remoteHost | Host reachable from the SSH server to connect to |
| remotePort | Port on the remote host |
| originAddr | Originator address reported to the server |
| originPort | Originator port reported to the server |