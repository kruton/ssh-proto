//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSigning](index.md)/[signWithKeyPair](sign-with-key-pair.md)

# signWithKeyPair

[jvm]\
fun [signWithKeyPair](sign-with-key-pair.md)(algorithmName: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Sign authentication data using a JCA [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html).

#### Return

SSH-encoded signature blob

#### Parameters

jvm

| | |
|---|---|
| algorithmName | SSH signature algorithm (e.g., &quot;ssh-ed25519&quot;, &quot;rsa-sha2-256&quot;) |
| keyPair | JCA key pair containing the private key |
| dataToSign | The data to sign (as provided by [AuthHandler.onSignatureRequest](../-auth-handler/on-signature-request.md)) |