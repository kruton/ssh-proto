//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[AuthResult](../index.md)/[Failure](index.md)

# Failure

[jvm]\
data class [Failure](index.md)(val allowedMethods: [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;) : [AuthResult](../index.md)

Server rejected credentials. allowedMethods lists methods still available to try.

## Constructors

| | |
|---|---|
| [Failure](-failure.md) | [jvm]<br>constructor(allowedMethods: [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;) |

## Properties

| Name | Summary |
|---|---|
| [allowedMethods](allowed-methods.md) | [jvm]<br>val [allowedMethods](allowed-methods.md): [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt; |