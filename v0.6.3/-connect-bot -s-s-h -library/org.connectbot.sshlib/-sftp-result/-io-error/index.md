//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SftpResult](../index.md)/[IoError](index.md)

# IoError

[jvm]\
data class [IoError](index.md)(val cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)) : [SftpResult](../index.md)&lt;[Nothing](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-nothing/index.html)&gt; 

Network or I/O error.

## Constructors

| | |
|---|---|
| [IoError](-io-error.md) | [jvm]<br>constructor(cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [cause](cause.md) | [jvm]<br>val [cause](cause.md): [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html) |

## Functions

| Name | Summary |
|---|---|
| [getOrNull](../../get-or-null.md) | [jvm]<br>fun &lt;[T](../../get-or-null.md)&gt; [SftpResult](../index.md)&lt;[T](../../get-or-null.md)&gt;.[getOrNull](../../get-or-null.md)(): [T](../../get-or-null.md)?<br>Convenience: extract value or null for success, throws nothing. |
| [getOrThrow](../../get-or-throw.md) | [jvm]<br>fun &lt;[T](../../get-or-throw.md)&gt; [SftpResult](../index.md)&lt;[T](../../get-or-throw.md)&gt;.[getOrThrow](../../get-or-throw.md)(): [T](../../get-or-throw.md)<br>Convenience: extract value or throw for interop with blocking APIs. |