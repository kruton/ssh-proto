//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkSignatureBlob](index.md)

# SkSignatureBlob

[jvm]\
object [SkSignatureBlob](index.md)

Packs an SK assertion into the OpenSSH SK signature wire format.

The output is what callers should return from [org.connectbot.sshlib.AuthHandler.onSignatureRequest](../../org.connectbot.sshlib/-auth-handler/on-signature-request.md) for an SK public key. The library writes it verbatim into the SSH publickey `USERAUTH_REQUEST` packet's signature field.

Format per OpenSSH `PROTOCOL.u2f` §3.2:

```kotlin
sk-ssh-ed25519@openssh.com:
  string  "sk-ssh-ed25519@openssh.com"
  string  rawEd25519Signature        (64 bytes)
  byte    flags
  uint32  counter

sk-ecdsa-sha2-nistp256@openssh.com:
  string  "sk-ecdsa-sha2-nistp256@openssh.com"
  string  sig_material               (mpint r || mpint s, RFC 5656)
  byte    flags
  uint32  counter
```

For ECDSA-P256, [pack](pack.md) accepts the DER `SEQUENCE { INTEGER r, INTEGER s }` format that CTAP2 returns and converts it to `mpint r || mpint s` internally.

The `flags` and `counter` parameters of [pack](pack.md) come from the CTAP2 GetAssertion response. Per OpenSSH `PROTOCOL.u2f` §3.2, the FIDO2 device sets `flags = SK_USER_PRESENCE_REQUIRED (0x01)` if user presence was tested and `| SK_USER_VERIFICATION_REQUIRED (0x04)` if user verification was also tested; `counter` is the device's monotonic signature counter.

## Properties

| Name | Summary |
|---|---|
| [FLAG_USER_PRESENCE](-f-l-a-g_-u-s-e-r_-p-r-e-s-e-n-c-e.md) | [jvm]<br>const val [FLAG_USER_PRESENCE](-f-l-a-g_-u-s-e-r_-p-r-e-s-e-n-c-e.md): [Byte](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte/index.html) = 1 |
| [FLAG_USER_VERIFICATION](-f-l-a-g_-u-s-e-r_-v-e-r-i-f-i-c-a-t-i-o-n.md) | [jvm]<br>const val [FLAG_USER_VERIFICATION](-f-l-a-g_-u-s-e-r_-v-e-r-i-f-i-c-a-t-i-o-n.md): [Byte](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte/index.html) = 4 |

## Functions

| Name | Summary |
|---|---|
| [pack](pack.md) | [jvm]<br>fun [pack](pack.md)(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawSignature: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), flags: [Byte](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte/index.html), counter: [UInt](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-u-int/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)<br>Pack an SK assertion into the OpenSSH SK signature blob. |