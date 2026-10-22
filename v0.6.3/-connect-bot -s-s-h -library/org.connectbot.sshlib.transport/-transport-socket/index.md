//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.transport](../index.md)/[TransportSocket](index.md)

# TransportSocket

[jvm]\
interface [TransportSocket](index.md) : [Closeable](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/Closeable.html)

Abstract socket interface to decouple from Ktor's Socket implementation.

## Properties

| Name | Summary |
|---|---|
| [isClosed](is-closed.md) | [jvm]<br>abstract val [isClosed](is-closed.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |

## Functions

| Name | Summary |
|---|---|
| [close](index.md#-1117130810%2FFunctions%2F-1357994179) | [jvm]<br>abstract fun [close](index.md#-1117130810%2FFunctions%2F-1357994179)() |
| [openReadChannel](open-read-channel.md) | [jvm]<br>abstract fun [openReadChannel](open-read-channel.md)(): ByteReadChannel |
| [openWriteChannel](open-write-channel.md) | [jvm]<br>abstract fun [openWriteChannel](open-write-channel.md)(autoFlush: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) = false): ByteWriteChannel |