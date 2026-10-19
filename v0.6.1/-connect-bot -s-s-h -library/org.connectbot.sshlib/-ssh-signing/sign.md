//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSigning](index.md)/[sign](sign.md)

# sign

[jvm]\
fun [sign](sign.md)(algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?, dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Sign authentication data using a private key.

#### Return

SSH-encoded signature blob

#### Parameters

jvm

| | |
|---|---|
| algorithmName | SSH signature algorithm (e.g., &quot;ssh-ed25519&quot;, &quot;rsa-sha2-256&quot;) |
| privateKeyData | PEM or OpenSSH private key contents |
| passphrase | Key passphrase, or null if unencrypted |
| dataToSign | The data to sign (as provided by [AuthHandler.onSignatureRequest](../-auth-handler/on-signature-request.md)) |

[jvm]\
fun [sign](sign.md)(algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), privateKeyData: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?, dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Sign authentication data using a private key.

#### Return

SSH-encoded signature blob

#### Parameters

jvm

| | |
|---|---|
| algorithmName | SSH signature algorithm (e.g., &quot;ssh-ed25519&quot;, &quot;rsa-sha2-256&quot;) |
| privateKeyData | PEM or OpenSSH private key contents as bytes |
| passphrase | Key passphrase, or null if unencrypted |
| dataToSign | The data to sign (as provided by [AuthHandler.onSignatureRequest](../-auth-handler/on-signature-request.md)) |