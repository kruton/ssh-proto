//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[Transport](index.md)/[write](write.md)

# write

[jvm]\
abstract suspend fun [write](write.md)(data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))

Write all bytes to the transport.

#### Parameters

jvm

| | |
|---|---|
| data | Bytes to write |

#### Throws

| | |
|---|---|
| [TransportException](../-transport-exception/index.md) | if the connection is closed or an error occurs |