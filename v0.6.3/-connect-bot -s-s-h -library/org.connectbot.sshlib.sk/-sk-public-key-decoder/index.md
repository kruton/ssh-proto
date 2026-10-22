//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkPublicKeyDecoder](index.md)

# SkPublicKeyDecoder

[jvm]\
object [SkPublicKeyDecoder](index.md)

Parses OpenSSH SK public-key wire blobs into an [SkPublicKey](../-sk-public-key/index.md).

This is the inverse of [SkPublicKeyEncoder.encode](../-sk-public-key-encoder/encode.md). Callers that already have raw key bytes can skip this; the decoder is provided so callers that parse `authorized_keys` or `ssh-keygen -t *-sk` files (which embed the pubkey blob inside an OpenSSH private-key envelope) don't have to write SSH-string framing logic themselves.

Strict: the entire input must be consumed.

## Functions

| Name | Summary |
|---|---|
| [decode](decode.md) | [jvm]<br>fun [decode](decode.md)(blob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SkPublicKey](../-sk-public-key/index.md)<br>Decode an SK public-key wire blob. |