//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[localPortForward](local-port-forward.md)

# localPortForward

[jvm]\
fun [localPortForward](local-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?

Start local port forwarding.

[jvm]\
fun [localPortForward](local-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?

Start local port forwarding bound to localhost.