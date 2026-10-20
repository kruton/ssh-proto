//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SftpResult](../index.md)/[Success](index.md)

# Success

[jvm]\
data class [Success](index.md)&lt;[T](index.md)&gt;(val value: [T](index.md)) : [SftpResult](../index.md)&lt;[T](index.md)&gt; 

Operation succeeded with value.

## Constructors

| | |
|---|---|
| [Success](-success.md) | [jvm]<br>constructor(value: [T](index.md)) |

## Properties

| Name | Summary |
|---|---|
| [value](value.md) | [jvm]<br>val [value](value.md): [T](index.md) |

## Functions

| Name | Summary |
|---|---|
| [getOrNull](../../get-or-null.md) | [jvm]<br>fun &lt;[T](../../get-or-null.md)&gt; [SftpResult](../index.md)&lt;[T](../../get-or-null.md)&gt;.[getOrNull](../../get-or-null.md)(): [T](../../get-or-null.md)?<br>Convenience: extract value or null for success, throws nothing. |
| [getOrThrow](../../get-or-throw.md) | [jvm]<br>fun &lt;[T](../../get-or-throw.md)&gt; [SftpResult](../index.md)&lt;[T](../../get-or-throw.md)&gt;.[getOrThrow](../../get-or-throw.md)(): [T](../../get-or-throw.md)<br>Convenience: extract value or throw for interop with blocking APIs. |