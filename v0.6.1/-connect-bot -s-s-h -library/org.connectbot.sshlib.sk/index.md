//[ConnectBot SSH Library](../../index.md)/[org.connectbot.sshlib.sk](index.md)

# Package-level declarations

## Types

| Name | Summary |
|---|---|
| [SkAlgorithm](-sk-algorithm/index.md) | [jvm]<br>enum [SkAlgorithm](-sk-algorithm/index.md) : [Enum](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-enum/index.html)&lt;[SkAlgorithm](-sk-algorithm/index.md)&gt; <br>OpenSSH FIDO2 / Security Key public-key algorithms. |
| [SkAuthHelpers](-sk-auth-helpers/index.md) | [jvm]<br>object [SkAuthHelpers](-sk-auth-helpers/index.md)<br>Convenience entry points for wiring SK keys into the [org.connectbot.sshlib.AuthHandler](../org.connectbot.sshlib/-auth-handler/index.md) flow. |
| [SkPublicKey](-sk-public-key/index.md) | [jvm]<br>data class [SkPublicKey](-sk-public-key/index.md)(val algorithm: [SkAlgorithm](-sk-algorithm/index.md), val rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), val application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html))<br>Decoded SK public key. |
| [SkPublicKeyDecoder](-sk-public-key-decoder/index.md) | [jvm]<br>object [SkPublicKeyDecoder](-sk-public-key-decoder/index.md)<br>Parses OpenSSH SK public-key wire blobs into an [SkPublicKey](-sk-public-key/index.md). |
| [SkPublicKeyEncoder](-sk-public-key-encoder/index.md) | [jvm]<br>object [SkPublicKeyEncoder](-sk-public-key-encoder/index.md)<br>Builds OpenSSH SK public-key wire blobs. |
| [SkSignatureBlob](-sk-signature-blob/index.md) | [jvm]<br>object [SkSignatureBlob](-sk-signature-blob/index.md)<br>Packs an SK assertion into the OpenSSH SK signature wire format. |