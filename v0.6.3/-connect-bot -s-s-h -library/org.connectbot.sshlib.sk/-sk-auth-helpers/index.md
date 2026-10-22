//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkAuthHelpers](index.md)

# SkAuthHelpers

[jvm]\
object [SkAuthHelpers](index.md)

Convenience entry points for wiring SK keys into the [org.connectbot.sshlib.AuthHandler](../../org.connectbot.sshlib/-auth-handler/index.md) flow.

Typical caller flow (caller owns the CTAP2 stack):

```kotlin
// 1. From your stored SK key data, build an AuthPublicKey:
val authKey = SkAuthHelpers.buildAuthPublicKey(
    algorithm = SkAlgorithm.ED25519,
    rawKey = storedRawEd25519PubKey,        // 32 bytes
    application = "ssh:",                   // RP id the credential is bound to
)

// 2. Return it from AuthHandler.onPublicKeysNeeded():
override suspend fun onPublicKeysNeeded() = listOf(authKey)

// 3. In AuthHandler.onSignatureRequest(), call your CTAP2 stack with
//    clientDataHash = SHA-256(dataToSign), then return SkSignatureBlob.pack(...).
override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray {
    val clientDataHash = sha256(dataToSign)
    val assertion = myCtap2.getAssertion(rpId = "ssh:", credentialId = ..., clientDataHash)
    return SkSignatureBlob.pack(
        algorithm = SkAlgorithm.ED25519,
        rawSignature = assertion.signature,     // raw 64 bytes for Ed25519, DER for ECDSA-P256
        flags = assertion.flags,                // 0x01 = UP, |0x04 if UV
        counter = assertion.counter,
    )
}
```

## Functions

| Name | Summary |
|---|---|
| [buildAuthPublicKey](build-auth-public-key.md) | [jvm]<br>fun [buildAuthPublicKey](build-auth-public-key.md)(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AuthPublicKey](../../org.connectbot.sshlib/-auth-public-key/index.md)<br>Build an [AuthPublicKey](../../org.connectbot.sshlib/-auth-public-key/index.md) for an SK credential, suitable for returning from [org.connectbot.sshlib.AuthHandler.onPublicKeysNeeded](../../org.connectbot.sshlib/-auth-handler/on-public-keys-needed.md). |