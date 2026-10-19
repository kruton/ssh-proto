//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkPublicKeyEncoder](index.md)

# SkPublicKeyEncoder

[jvm]\
object [SkPublicKeyEncoder](index.md)

Builds OpenSSH SK public-key wire blobs.

The output is the byte sequence that appears in `authorized_keys` (base64-encoded after the algorithm name) and in the `public key blob` field of SSH publickey auth requests.

Format per OpenSSH `PROTOCOL.u2f` §3.1:

```kotlin
sk-ssh-ed25519@openssh.com:
  string  "sk-ssh-ed25519@openssh.com"
  string  rawEd25519PublicKey      (32 bytes)
  string  application              (e.g. "ssh:")

sk-ecdsa-sha2-nistp256@openssh.com:
  string  "sk-ecdsa-sha2-nistp256@openssh.com"
  string  "nistp256"
  string  ecPoint                  (uncompressed SEC1: 0x04 || X(32) || Y(32), 65 bytes)
  string  application
```

## Functions

| Name | Summary |
|---|---|
| [encode](encode.md) | [jvm]<br>fun [encode](encode.md)(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Build the SK public-key wire blob. |