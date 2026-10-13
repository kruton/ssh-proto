//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[authenticatePublicKey](authenticate-public-key.md)

# authenticatePublicKey

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null)

Authenticate using public key authentication (RFC 4252 §7).

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| privateKeyData | Private key file contents |
| passphrase | Passphrase for encrypted keys, or null |

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if authentication fails or an error occurs |

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [authenticatePublicKey](authenticate-public-key.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null)

Authenticate using public key authentication (RFC 4252 §7).

#### Parameters

jvm

| | |
|---|---|
| username | SSH username |
| privateKeyData | Private key file contents as a string |
| passphrase | Passphrase for encrypted keys, or null |

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if authentication fails or an error occurs |