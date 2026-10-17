//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkSignatureBlob](index.md)/[pack](pack.md)

# pack

[jvm]\
fun [pack](pack.md)(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawSignature: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), flags: [Byte](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte/index.html), counter: [UInt](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-u-int/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Pack an SK assertion into the OpenSSH SK signature blob.

#### Return

The full OpenSSH SK signature wire blob.

#### Parameters

jvm

| | |
|---|---|
| algorithm | SK algorithm. |
| rawSignature | For [SkAlgorithm.ED25519](../-sk-algorithm/-e-d25519/index.md): the raw 64-byte Ed25519 signature from the authenticator. For [SkAlgorithm.ECDSA_P256](../-sk-algorithm/-e-c-d-s-a_-p256/index.md): the DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` signature from CTAP2. |
| flags | Authenticator flags byte (see [FLAG_USER_PRESENCE](-f-l-a-g_-u-s-e-r_-p-r-e-s-e-n-c-e.md), [FLAG_USER_VERIFICATION](-f-l-a-g_-u-s-e-r_-v-e-r-i-f-i-c-a-t-i-o-n.md)). |
| counter | Authenticator signature counter (big-endian uint32 on the wire). |

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if [rawSignature](pack.md) has the wrong size or is malformed. |