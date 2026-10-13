//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SftpResult](../index.md)/[ServerError](index.md)

# ServerError

[jvm]\
data class [ServerError](index.md)(val statusCode: [SftpStatusCode](../../-sftp-status-code/index.md), val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) : [SftpResult](../index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; 

SFTP server returned an error status.

## Constructors

| | |
|---|---|
| [ServerError](-server-error.md) | [jvm]<br>constructor(statusCode: [SftpStatusCode](../../-sftp-status-code/index.md), message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [message](message.md) | [jvm]<br>val [message](message.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [statusCode](status-code.md) | [jvm]<br>val [statusCode](status-code.md): [SftpStatusCode](../../-sftp-status-code/index.md) |

## Functions

| Name | Summary |
|---|---|
| [getOrNull](../../get-or-null.md) | [jvm]<br>fun &lt;[T](../../get-or-null.md)&gt; [SftpResult](../index.md)&lt;[T](../../get-or-null.md)&gt;.[getOrNull](../../get-or-null.md)(): [T](../../get-or-null.md)?<br>Convenience: extract value or null for success, throws nothing. |
| [getOrThrow](../../get-or-throw.md) | [jvm]<br>fun &lt;[T](../../get-or-throw.md)&gt; [SftpResult](../index.md)&lt;[T](../../get-or-throw.md)&gt;.[getOrThrow](../../get-or-throw.md)(): [T](../../get-or-throw.md)<br>Convenience: extract value or throw for interop with blocking APIs. |