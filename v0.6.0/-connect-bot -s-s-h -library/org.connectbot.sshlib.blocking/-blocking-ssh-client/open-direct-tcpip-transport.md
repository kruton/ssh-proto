//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[openDirectTcpipTransport](open-direct-tcpip-transport.md)

# openDirectTcpipTransport

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [openDirectTcpipTransport](open-direct-tcpip-transport.md)(remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;127.0.0.1&quot;, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md)?

Create a [org.connectbot.sshlib.transport.TransportFactory](../../org.connectbot.sshlib.transport/-transport-factory/index.md) that tunnels through this SSH connection.