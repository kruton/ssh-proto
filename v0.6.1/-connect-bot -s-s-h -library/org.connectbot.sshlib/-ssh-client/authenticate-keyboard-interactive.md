//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)

# authenticateKeyboardInteractive

[jvm]\
suspend fun [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), callback: [KeyboardInteractiveCallback](../-keyboard-interactive-callback/index.md)): [AuthResult](../-auth-result/index.md)

Authenticate using keyboard-interactive authentication (RFC 4256).

#### Return

[AuthResult](../-auth-result/index.md) indicating success or failure

[AuthResult.Error](../-auth-result/-error/index.md) if [connect](connect.md) has not been called successfully

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| callback | Receives prompts from the server and provides responses |