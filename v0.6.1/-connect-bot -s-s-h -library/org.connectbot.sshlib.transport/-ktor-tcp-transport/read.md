//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[KtorTcpTransport](index.md)/[read](read.md)

# read

[jvm]\
open suspend override fun [read](read.md)(count: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Read exactly [count](../-transport/read.md) bytes from the transport.

#### Return

ByteArray containing exactly [count](../-transport/read.md) bytes

#### Parameters

jvm

| | |
|---|---|
| count | Number of bytes to read |

#### Throws

| | |
|---|---|
| [TransportException](../-transport-exception/index.md) | if the connection is closed or an error occurs |