//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[authenticate](authenticate.md)

# authenticate

[jvm]\
fun [authenticate](authenticate.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), handler: [AuthHandler](../../org.connectbot.sshlib/-auth-handler/index.md))

Authenticate using the strategy-based [AuthHandler](../../org.connectbot.sshlib/-auth-handler/index.md) flow.

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| handler | Callback handler providing authentication materials |

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if authentication fails or an error occurs |