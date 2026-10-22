//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkPublicKeyDecoder](index.md)/[decode](decode.md)

# decode

[jvm]\
fun [decode](decode.md)(blob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SkPublicKey](../-sk-public-key/index.md)

Decode an SK public-key wire blob.

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if the blob is malformed, has trailing bytes, or uses an algorithm name that is not one of the known SK algorithms. |