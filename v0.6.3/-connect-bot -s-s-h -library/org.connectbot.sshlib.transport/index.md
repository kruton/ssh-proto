//[ConnectBot SSH Library](../../index.md)/[org.connectbot.sshlib.transport](index.md)

# Package-level declarations

## Types

| Name | Summary |
|---|---|
| [AddressResolver](-address-resolver/index.md) | [jvm]<br>interface [AddressResolver](-address-resolver/index.md)<br>Resolves hostnames to IP addresses. |
| [IpVersion](-ip-version/index.md) | [jvm]<br>enum [IpVersion](-ip-version/index.md) : [Enum](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-enum/index.html)&lt;[IpVersion](-ip-version/index.md)&gt; <br>Controls which IP address families are used for TCP connections. |
| [KtorTcpTransport](-ktor-tcp-transport/index.md) | [jvm]<br>class [KtorTcpTransport](-ktor-tcp-transport/index.md) : [Transport](-transport/index.md)<br>TCP socket transport implementation using Ktor. |
| [KtorTcpTransportFactory](-ktor-tcp-transport-factory/index.md) | [jvm]<br>class [KtorTcpTransportFactory](-ktor-tcp-transport-factory/index.md)(host: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22, ipVersion: [IpVersion](-ip-version/index.md) = IpVersion.AUTO) : [TransportFactory](-transport-factory/index.md)<br>Factory that creates [KtorTcpTransport](-ktor-tcp-transport/index.md) instances for TCP connections. |
| [TcpSocketFactory](-tcp-socket-factory/index.md) | [jvm]<br>interface [TcpSocketFactory](-tcp-socket-factory/index.md)<br>Creates TCP sockets. |
| [Transport](-transport/index.md) | [jvm]<br>interface [Transport](-transport/index.md)<br>Transport abstraction for SSH connections. |
| [TransportException](-transport-exception/index.md) | [jvm]<br>class [TransportException](-transport-exception/index.md)(message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [SshException](../org.connectbot.sshlib/-ssh-exception/index.md)<br>Exception thrown when transport operations fail. |
| [TransportFactory](-transport-factory/index.md) | [jvm]<br>fun interface [TransportFactory](-transport-factory/index.md)<br>Factory for creating transport connections. |
| [TransportSocket](-transport-socket/index.md) | [jvm]<br>interface [TransportSocket](-transport-socket/index.md) : [Closeable](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/Closeable.html)<br>Abstract socket interface to decouple from Ktor's Socket implementation. |