//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)

# authenticateKeyboardInteractive

[jvm]\
fun [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), callback: [KeyboardInteractiveCallback](../../org.connectbot.sshlib/-keyboard-interactive-callback/index.md))

Authenticate using keyboard-interactive authentication (RFC 4256).

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| callback | Receives prompts from the server and provides responses |

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if authentication fails or an error occurs |