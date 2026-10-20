//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthResult](index.md)

# AuthResult

sealed interface [AuthResult](index.md)

Result of [SshClient.authenticatePassword](../-ssh-client/authenticate-password.md), [SshClient.authenticatePublicKey](../-ssh-client/authenticate-public-key.md), [SshClient.authenticateKeyboardInteractive](../-ssh-client/authenticate-keyboard-interactive.md), and [SshClient.authenticate](../-ssh-client/authenticate.md).

#### Inheritors

| |
|---|
| [Success](-success/index.md) |
| [Failure](-failure/index.md) |
| [Error](-error/index.md) |

## Types

| Name | Summary |
|---|---|
| [Error](-error/index.md) | [jvm]<br>data class [Error](-error/index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [AuthResult](index.md)<br>Protocol or state error — not a credentials problem. |
| [Failure](-failure/index.md) | [jvm]<br>data class [Failure](-failure/index.md)(val allowedMethods: [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;) : [AuthResult](index.md)<br>Server rejected credentials. allowedMethods lists methods still available to try. |
| [Success](-success/index.md) | [jvm]<br>data object [Success](-success/index.md) : [AuthResult](index.md) |