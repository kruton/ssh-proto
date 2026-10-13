//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSigning](index.md)/[encodePublicKey](encode-public-key.md)

# encodePublicKey

[jvm]\
fun [encodePublicKey](encode-public-key.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html)): [AuthPublicKey](../-auth-public-key/index.md)

Encode a [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html)'s public key to an [AuthPublicKey](../-auth-public-key/index.md) for use with [AuthHandler.onPublicKeysNeeded](../-auth-handler/on-public-keys-needed.md).

The SSH algorithm name is inferred from the key type (e.g., Ed25519 → &quot;ssh-ed25519&quot;, RSA → &quot;ssh-rsa&quot;). For RSA keys that need a specific signature algorithm like &quot;rsa-sha2-256&quot;, construct the [AuthPublicKey](../-auth-public-key/index.md) with the desired algorithm name using the returned blob.

#### Return

The corresponding [AuthPublicKey](../-auth-public-key/index.md)

#### Parameters

jvm

| | |
|---|---|
| keyPair | JCA key pair |