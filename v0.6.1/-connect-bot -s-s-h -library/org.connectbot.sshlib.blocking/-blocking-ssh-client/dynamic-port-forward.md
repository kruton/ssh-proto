//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[dynamicPortForward](dynamic-port-forward.md)

# dynamicPortForward

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [dynamicPortForward](dynamic-port-forward.md)(bindAddress: [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html), authenticator: [Socks5Authenticator](../../org.connectbot.sshlib/-socks5-authenticator/index.md)? = null): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?

Start dynamic (SOCKS5) port forwarding.

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [dynamicPortForward](dynamic-port-forward.md)(bindPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), authenticator: [Socks5Authenticator](../../org.connectbot.sshlib/-socks5-authenticator/index.md)? = null): [PortForwarder](../../org.connectbot.sshlib/-port-forwarder/index.md)?

Start dynamic (SOCKS5) port forwarding bound to localhost.