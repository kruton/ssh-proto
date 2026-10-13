//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[KtorTcpTransport](index.md)

# KtorTcpTransport

class [KtorTcpTransport](index.md) : [Transport](../-transport/index.md)

TCP socket transport implementation using Ktor.

This provides a lightweight TCP transport layer using Ktor's networking APIs, suitable for use on Android and JVM platforms.

#### Parameters

jvm

| | |
|---|---|
| host | Remote host to connect to |
| port | Remote port (default 22 for SSH) |

## Constructors

| | |
|---|---|
| [KtorTcpTransport](-ktor-tcp-transport.md) | [jvm]<br>constructor(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, ipVersion: [IpVersion](../-ip-version/index.md) = IpVersion.AUTO) |

## Properties

| Name | Summary |
|---|---|
| [isConnected](is-connected.md) | [jvm]<br>open override val [isConnected](is-connected.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Check if the transport is still connected. |

## Functions

| Name | Summary |
|---|---|
| [close](close.md) | [jvm]<br>open suspend override fun [close](close.md)()<br>Close the transport connection. |
| [connect](connect.md) | [jvm]<br>suspend fun [connect](connect.md)()<br>Connect to the remote host. Must be called before any read/write operations. |
| [getLocalAddress](get-local-address.md) | [jvm]<br>fun [getLocalAddress](get-local-address.md)(): [InetSocketAddress](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/InetSocketAddress.html)?<br>Local TCP address assigned to the connected socket, or `null` before connection, after close, or when the injected socket does not expose it. |
| [read](read.md) | [jvm]<br>open suspend override fun [read](read.md)(count: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Read exactly [count](../-transport/read.md) bytes from the transport. |
| [write](write.md) | [jvm]<br>open suspend override fun [write](write.md)(data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))<br>Write all bytes to the transport. |