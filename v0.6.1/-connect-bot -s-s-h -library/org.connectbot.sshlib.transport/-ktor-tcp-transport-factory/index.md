//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[KtorTcpTransportFactory](index.md)

# KtorTcpTransportFactory

class [KtorTcpTransportFactory](index.md)(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, ipVersion: [IpVersion](../-ip-version/index.md) = IpVersion.AUTO) : [TransportFactory](../-transport-factory/index.md)

Factory that creates [KtorTcpTransport](../-ktor-tcp-transport/index.md) instances for TCP connections.

This is the default transport factory used when connecting to SSH servers over TCP/IP.

#### Parameters

jvm

| | |
|---|---|
| host | The hostname or IP address to connect to |
| port | The port number (default 22) |
| ipVersion | Which address families to use (default [IpVersion.AUTO](../-ip-version/-a-u-t-o/index.md)) |

## Constructors

| | |
|---|---|
| [KtorTcpTransportFactory](-ktor-tcp-transport-factory.md) | [jvm]<br>constructor(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, ipVersion: [IpVersion](../-ip-version/index.md) = IpVersion.AUTO) |

## Functions

| Name | Summary |
|---|---|
| [create](create.md) | [jvm]<br>open suspend override fun [create](create.md)(): [Transport](../-transport/index.md)<br>Create and connect a new transport instance. |