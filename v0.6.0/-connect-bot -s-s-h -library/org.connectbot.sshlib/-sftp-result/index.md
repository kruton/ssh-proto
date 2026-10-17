//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpResult](index.md)

# SftpResult

sealed interface [SftpResult](index.md)&lt;out [T](index.md)&gt;

Result type for SFTP operations. Replaces thrown exceptions with a sealed interface so callers can handle errors structurally.

#### Inheritors

| |
|---|
| [Success](-success/index.md) |
| [ServerError](-server-error/index.md) |
| [ProtocolError](-protocol-error/index.md) |
| [IoError](-io-error/index.md) |

## Types

| Name | Summary |
|---|---|
| [IoError](-io-error/index.md) | [jvm]<br>data class [IoError](-io-error/index.md)(val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)) : [SftpResult](index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; <br>Network or I/O error. |
| [ProtocolError](-protocol-error/index.md) | [jvm]<br>data class [ProtocolError](-protocol-error/index.md)(val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) : [SftpResult](index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; <br>SFTP protocol violation (unexpected packet type, malformed data). |
| [ServerError](-server-error/index.md) | [jvm]<br>data class [ServerError](-server-error/index.md)(val statusCode: [SftpStatusCode](../-sftp-status-code/index.md), val message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)) : [SftpResult](index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; <br>SFTP server returned an error status. |
| [Success](-success/index.md) | [jvm]<br>data class [Success](-success/index.md)&lt;[T](-success/index.md)&gt;(val value: [T](-success/index.md)) : [SftpResult](index.md)&lt;[T](-success/index.md)&gt; <br>Operation succeeded with value. |

## Functions

| Name | Summary |
|---|---|
| [getOrNull](../get-or-null.md) | [jvm]<br>fun &lt;[T](../get-or-null.md)&gt; [SftpResult](index.md)&lt;[T](../get-or-null.md)&gt;.[getOrNull](../get-or-null.md)(): [T](../get-or-null.md)?<br>Convenience: extract value or null for success, throws nothing. |
| [getOrThrow](../get-or-throw.md) | [jvm]<br>fun &lt;[T](../get-or-throw.md)&gt; [SftpResult](index.md)&lt;[T](../get-or-throw.md)&gt;.[getOrThrow](../get-or-throw.md)(): [T](../get-or-throw.md)<br>Convenience: extract value or throw for interop with blocking APIs. |