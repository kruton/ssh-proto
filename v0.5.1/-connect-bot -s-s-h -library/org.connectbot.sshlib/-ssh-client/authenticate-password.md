//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[authenticatePassword](authenticate-password.md)

# authenticatePassword

[jvm]\
suspend fun [authenticatePassword](authenticate-password.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AuthResult](../-auth-result/index.md)

Authenticate using password authentication.

#### Return

[AuthResult](../-auth-result/index.md) indicating success or failure

[AuthResult.Error](../-auth-result/-error/index.md) if [connect](connect.md) has not been called successfully

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| password | SSH password |