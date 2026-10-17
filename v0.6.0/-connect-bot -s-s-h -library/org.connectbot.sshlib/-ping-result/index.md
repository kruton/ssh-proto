//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[PingResult](index.md)

# PingResult

sealed class [PingResult](index.md)

Result of a [SshClient.ping](../-ssh-client/ping.md) call.

#### Inheritors

| |
|---|
| [Success](-success/index.md) |
| [NotSupported](-not-supported/index.md) |
| [NotAuthenticated](-not-authenticated/index.md) |
| [Failure](-failure/index.md) |

## Types

| Name | Summary |
|---|---|
| [Failure](-failure/index.md) | [jvm]<br>data class [Failure](-failure/index.md)(val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)) : [PingResult](index.md)<br>An error occurred while sending the ping or waiting for the reply. |
| [NotAuthenticated](-not-authenticated/index.md) | [jvm]<br>data object [NotAuthenticated](-not-authenticated/index.md) : [PingResult](index.md)<br>There is no active authenticated connection. |
| [NotSupported](-not-supported/index.md) | [jvm]<br>data object [NotSupported](-not-supported/index.md) : [PingResult](index.md)<br>The server did not advertise ping support via SSH2_MSG_EXT_INFO. |
| [Success](-success/index.md) | [jvm]<br>data class [Success](-success/index.md)(val elapsedNs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)) : [PingResult](index.md)<br>The server replied; elapsedNs is the round-trip time in nanoseconds. |