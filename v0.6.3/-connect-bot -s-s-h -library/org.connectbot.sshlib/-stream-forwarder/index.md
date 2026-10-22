//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[StreamForwarder](index.md)

# StreamForwarder

[jvm]\
interface [StreamForwarder](index.md) : [AutoCloseable](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/AutoCloseable.html)

Handle to an active stream forwarding through SSH.

Unlike [PortForwarder](../-port-forwarder/index.md), this does not bind a local port. Instead it forwards data between caller-provided streams and an SSH direct-tcpip channel.

## Properties

| Name | Summary |
|---|---|
| [isActive](is-active.md) | [jvm]<br>abstract val [isActive](is-active.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |

## Functions

| Name | Summary |
|---|---|
| [close](close.md) | [jvm]<br>open override fun [close](close.md)() |
| [stop](stop.md) | [jvm]<br>abstract suspend fun [stop](stop.md)() |