//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[authenticatePublicKey](authenticate-public-key.md)

# authenticatePublicKey

[jvm]\
suspend fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [AuthResult](../-auth-result/index.md)

Authenticate using public key authentication (RFC 4252 §7).

#### Return

[AuthResult](../-auth-result/index.md) indicating success or failure

[AuthResult.Error](../-auth-result/-error/index.md) if [connect](connect.md) has not been called successfully

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| privateKeyData | Private key file contents |
| passphrase | Passphrase for encrypted keys, or null |

[jvm]\
suspend fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [AuthResult](../-auth-result/index.md)

Authenticate using public key authentication (RFC 4252 §7).

#### Return

[AuthResult](../-auth-result/index.md) indicating success or failure

[AuthResult.Error](../-auth-result/-error/index.md) if [connect](connect.md) has not been called successfully

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| privateKeyData | Private key file contents as a string |
| passphrase | Passphrase for encrypted keys, or null |