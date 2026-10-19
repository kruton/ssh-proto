//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[PortForwarder](index.md)

# PortForwarder

[jvm]\
interface [PortForwarder](index.md) : [AutoCloseable](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/AutoCloseable.html)

Handle to an active port forwarding.

For local and dynamic forwarding, [boundHost](bound-host.md) and [boundPort](bound-port.md) are the local bind address. For remote forwarding, they are the remote bind address the server is listening on.

## Properties

| Name | Summary |
|---|---|
| [boundHost](bound-host.md) | [jvm]<br>abstract val [boundHost](bound-host.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [boundPort](bound-port.md) | [jvm]<br>abstract val [boundPort](bound-port.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [isActive](is-active.md) | [jvm]<br>abstract val [isActive](is-active.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |

## Functions

| Name | Summary |
|---|---|
| [close](close.md) | [jvm]<br>open override fun [close](close.md)() |
| [stop](stop.md) | [jvm]<br>abstract suspend fun [stop](stop.md)() |