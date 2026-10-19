//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[KtorTcpTransport](index.md)/[getLocalAddress](get-local-address.md)

# getLocalAddress

[jvm]\
fun [getLocalAddress](get-local-address.md)(): [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html)?

Local TCP address assigned to the connected socket, or `null` before connection, after close, or when the injected socket does not expose it.