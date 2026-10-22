//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SessionExit](index.md)

# SessionExit

sealed interface [SessionExit](index.md)

How the remote process on a session channel terminated (RFC 4254 section 6.10).

#### Inheritors

| |
|---|
| [Status](-status/index.md) |
| [Signal](-signal/index.md) |

## Types

| Name | Summary |
|---|---|
| [Signal](-signal/index.md) | [jvm]<br>data class [Signal](-signal/index.md)(val signalName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val coreDumped: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html), val errorMessage: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) : [SessionExit](index.md)<br>The remote process was terminated by a signal (`exit-signal`). |
| [Status](-status/index.md) | [jvm]<br>data class [Status](-status/index.md)(val code: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)) : [SessionExit](index.md)<br>The remote process exited normally with code (`exit-status`). |