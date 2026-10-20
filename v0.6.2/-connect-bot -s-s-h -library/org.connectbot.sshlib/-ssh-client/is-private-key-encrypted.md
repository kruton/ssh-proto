//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[isPrivateKeyEncrypted](is-private-key-encrypted.md)

# isPrivateKeyEncrypted

[jvm]\
fun [isPrivateKeyEncrypted](is-private-key-encrypted.md)(privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Check if the provided private key data is encrypted and requires a passphrase.

#### Return

true if the key is encrypted

#### Parameters

jvm

| | |
|---|---|
| privateKeyData | Private key file contents |

[jvm]\
fun [isPrivateKeyEncrypted](is-private-key-encrypted.md)(privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Check if the provided private key data is encrypted and requires a passphrase.

#### Return

true if the key is encrypted

#### Parameters

jvm

| | |
|---|---|
| privateKeyData | Private key file contents as a string |