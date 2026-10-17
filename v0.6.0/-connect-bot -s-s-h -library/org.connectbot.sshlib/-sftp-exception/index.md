//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpException](index.md)

# SftpException

class [SftpException](index.md)(val statusCode: [SftpStatusCode](../-sftp-status-code/index.md), message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) : [SshException](../-ssh-exception/index.md)

Exception thrown for SFTP protocol errors.

#### Parameters

jvm

| | |
|---|---|
| statusCode | The SFTP status code from the server |
| message | Human-readable error message |

## Constructors

| | |
|---|---|
| [SftpException](-sftp-exception.md) | [jvm]<br>constructor(statusCode: [SftpStatusCode](../-sftp-status-code/index.md), message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), cause: [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? = null) |

## Properties

| Name | Summary |
|---|---|
| [cause](../../org.connectbot.sshlib.transport/-transport-exception/index.md#-654012527%2FProperties%2F-1357994179) | [jvm]<br>open val [cause](../../org.connectbot.sshlib.transport/-transport-exception/index.md#-654012527%2FProperties%2F-1357994179): [Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)? |
| [message](../../org.connectbot.sshlib.transport/-transport-exception/index.md#1824300659%2FProperties%2F-1357994179) | [jvm]<br>open val [message](../../org.connectbot.sshlib.transport/-transport-exception/index.md#1824300659%2FProperties%2F-1357994179): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? |
| [statusCode](status-code.md) | [jvm]<br>val [statusCode](status-code.md): [SftpStatusCode](../-sftp-status-code/index.md) |

## Functions

| Name | Summary |
|---|---|
| [toString](to-string.md) | [jvm]<br>open override fun [toString](to-string.md)(): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |