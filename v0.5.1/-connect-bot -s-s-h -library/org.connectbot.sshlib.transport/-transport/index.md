//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[Transport](index.md)

# Transport

interface [Transport](index.md)

Transport abstraction for SSH connections.

This interface allows SSH to work over any byte stream transport, not just TCP sockets. Implementations could include:

- 
   TCP sockets (via Ktor or other libraries)
- 
   Unix domain sockets
- 
   Serial ports
- 
   Custom transport layers

#### Inheritors

| |
|---|
| [KtorTcpTransport](../-ktor-tcp-transport/index.md) |

## Properties

| Name | Summary |
|---|---|
| [isConnected](is-connected.md) | [jvm]<br>abstract val [isConnected](is-connected.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Check if the transport is still connected. |

## Functions

| Name | Summary |
|---|---|
| [close](close.md) | [jvm]<br>abstract suspend fun [close](close.md)()<br>Close the transport connection. |
| [read](read.md) | [jvm]<br>abstract suspend fun [read](read.md)(count: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Read exactly [count](read.md) bytes from the transport. |
| [write](write.md) | [jvm]<br>abstract suspend fun [write](write.md)(data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))<br>Write all bytes to the transport. |