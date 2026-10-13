//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSigning](index.md)/[encodePublicKeyBlob](encode-public-key-blob.md)

# encodePublicKeyBlob

[jvm]\
fun [encodePublicKeyBlob](encode-public-key-blob.md)(publicKey: [PublicKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/PublicKey.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Encode a [PublicKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/PublicKey.html) to its raw SSH wire-format public key blob.

The key type is inferred from the JCA key (e.g., Ed25519 → &quot;ssh-ed25519&quot;, RSA → &quot;ssh-rsa&quot;).

#### Return

SSH wire-format public key blob

#### Parameters

jvm

| | |
|---|---|
| publicKey | JCA public key |