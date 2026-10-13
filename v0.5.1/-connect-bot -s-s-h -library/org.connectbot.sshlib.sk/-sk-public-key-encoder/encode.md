//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkPublicKeyEncoder](index.md)/[encode](encode.md)

# encode

[jvm]\
fun [encode](encode.md)(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)

Build the SK public-key wire blob.

#### Parameters

jvm

| | |
|---|---|
| algorithm | SK algorithm. |
| rawKey | For [SkAlgorithm.ED25519](../-sk-algorithm/-e-d25519/index.md) the 32-byte raw Ed25519 public key. For [SkAlgorithm.ECDSA_P256](../-sk-algorithm/-e-c-d-s-a_-p256/index.md) the 65-byte uncompressed SEC1 point (`0x04 || X(32) || Y(32)`). |
| application | Relying-party identifier (e.g. `"ssh:"`). |

#### Throws

| | |
|---|---|
| [SshException](../../org.connectbot.sshlib/-ssh-exception/index.md) | if [rawKey](encode.md) has the wrong size for the algorithm, or if the ECDSA point is malformed. |