//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentResult](index.md)

# AgentResult

sealed interface [AgentResult](index.md)&lt;out [T](index.md)&gt;

Result of an [AgentProvider](../-agent-provider/index.md) callback.

Provider failures are values rather than thrown exceptions so an agent backend failure cannot terminate the SSH connection's packet loop.

#### Inheritors

| |
|---|
| [Success](-success/index.md) |
| [Failure](-failure/index.md) |

## Types

| Name | Summary |
|---|---|
| [Failure](-failure/index.md) | [jvm]<br>data class [Failure](-failure/index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [AgentResult](index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; <br>The provider could not complete the request. |
| [Success](-success/index.md) | [jvm]<br>data class [Success](-success/index.md)&lt;[T](-success/index.md)&gt;(val value: [T](-success/index.md)) : [AgentResult](index.md)&lt;[T](-success/index.md)&gt; <br>The provider completed successfully with value. |