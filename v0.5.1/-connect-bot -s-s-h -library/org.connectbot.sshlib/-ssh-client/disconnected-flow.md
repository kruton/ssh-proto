//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[disconnectedFlow](disconnected-flow.md)

# disconnectedFlow

[jvm]\
val [disconnectedFlow](disconnected-flow.md): SharedFlow&lt;[Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)?&gt;

Emits when the connection drops unexpectedly.

The value is the [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html) that caused the disconnection (e.g., transport error), or `null` if the server sent a clean SSH_MSG_DISCONNECT.

This flow does **not** emit when [disconnect](disconnect.md) is called by the caller.