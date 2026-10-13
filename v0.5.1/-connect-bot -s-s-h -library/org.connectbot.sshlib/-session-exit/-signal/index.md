//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SessionExit](../index.md)/[Signal](index.md)

# Signal

data class [Signal](index.md)(val signalName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val coreDumped: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html), val errorMessage: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) : [SessionExit](../index.md)

The remote process was terminated by a signal (`exit-signal`).

#### Parameters

jvm

| | |
|---|---|
| signalName | Signal name without the &quot;SIG&quot; prefix (e.g. &quot;KILL&quot;) |
| coreDumped | Whether a core dump was produced |
| errorMessage | Additional textual explanation from the server; may be empty |

## Constructors

| | |
|---|---|
| [Signal](-signal.md) | [jvm]<br>constructor(signalName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), coreDumped: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html), errorMessage: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [coreDumped](core-dumped.md) | [jvm]<br>val [coreDumped](core-dumped.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [errorMessage](error-message.md) | [jvm]<br>val [errorMessage](error-message.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [signalName](signal-name.md) | [jvm]<br>val [signalName](signal-name.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |