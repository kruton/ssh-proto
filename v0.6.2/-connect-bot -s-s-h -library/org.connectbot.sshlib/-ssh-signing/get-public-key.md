//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSigning](index.md)/[getPublicKey](get-public-key.md)

# getPublicKey

[jvm]\
fun [getPublicKey](get-public-key.md)(algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?): [AuthPublicKey](../-auth-public-key/index.md)

Extract the [AuthPublicKey](../-auth-public-key/index.md) from a private key for use with [AuthHandler.onPublicKeysNeeded](../-auth-handler/on-public-keys-needed.md).

#### Return

The corresponding public key for probing

#### Parameters

jvm

| | |
|---|---|
| algorithmName | SSH algorithm name (e.g., &quot;ssh-ed25519&quot;, &quot;rsa-sha2-256&quot;) |
| privateKeyData | PEM or OpenSSH private key contents |
| passphrase | Key passphrase, or null if unencrypted |

[jvm]\
fun [getPublicKey](get-public-key.md)(algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?): [AuthPublicKey](../-auth-public-key/index.md)

Extract the [AuthPublicKey](../-auth-public-key/index.md) from a private key for use with [AuthHandler.onPublicKeysNeeded](../-auth-handler/on-public-keys-needed.md).

#### Return

The corresponding public key for probing

#### Parameters

jvm

| | |
|---|---|
| algorithmName | SSH algorithm name (e.g., &quot;ssh-ed25519&quot;, &quot;rsa-sha2-256&quot;) |
| privateKeyData | PEM or OpenSSH private key contents as bytes |
| passphrase | Key passphrase, or null if unencrypted |