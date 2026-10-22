//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[AuthResult](../index.md)/[Error](index.md)

# Error

[jvm]\
data class [Error](index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [AuthResult](../index.md)

Protocol or state error — not a credentials problem.

## Constructors

| | |
|---|---|
| [Error](-error.md) | [jvm]<br>constructor(message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) |

## Properties

| Name | Summary |
|---|---|
| [cause](cause.md) | [jvm]<br>val [cause](cause.md): [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? |
| [message](message.md) | [jvm]<br>val [message](message.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |