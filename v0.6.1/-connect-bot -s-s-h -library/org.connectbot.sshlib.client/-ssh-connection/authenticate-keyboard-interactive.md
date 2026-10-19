//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SshConnection](index.md)/[authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)

# authenticateKeyboardInteractive

[jvm]\
suspend fun [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), callback: [KeyboardInteractiveCallback](../../org.connectbot.sshlib/-keyboard-interactive-callback/index.md)): [AuthResult](../../org.connectbot.sshlib/-auth-result/index.md)

Authenticate using keyboard-interactive (RFC 4256).

#### Parameters

jvm

| | |
|---|---|
| username | Username |
| callback | Callback that receives prompts and provides responses |