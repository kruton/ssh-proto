//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[authenticate](authenticate.md)

# authenticate

[jvm]\
suspend fun [authenticate](authenticate.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), handler: [AuthHandler](../-auth-handler/index.md)): [AuthResult](../-auth-result/index.md)

Authenticate using the strategy-based [AuthHandler](../-auth-handler/index.md) flow.

The library drives the authentication per RFC 4252, calling back into the handler for materials. The flow is: none → publickey probe → sign → keyboard-interactive → password.

#### Return

[AuthResult](../-auth-result/index.md) indicating success or failure

[AuthResult.Error](../-auth-result/-error/index.md) if [connect](connect.md) has not been called successfully

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| handler | Callback handler providing authentication materials |