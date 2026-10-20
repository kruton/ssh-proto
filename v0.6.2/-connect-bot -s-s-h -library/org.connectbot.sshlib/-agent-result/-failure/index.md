//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[AgentResult](../index.md)/[Failure](index.md)

# Failure

[jvm]\
data class [Failure](index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [AgentResult](../index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; 

The provider could not complete the request.

## Constructors

| | |
|---|---|
| [Failure](-failure.md) | [jvm]<br>constructor(message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) |

## Properties

| Name | Summary |
|---|---|
| [cause](cause.md) | [jvm]<br>val [cause](cause.md): [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? |
| [message](message.md) | [jvm]<br>val [message](message.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |