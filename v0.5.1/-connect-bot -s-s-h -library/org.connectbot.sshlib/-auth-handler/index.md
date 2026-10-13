//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthHandler](index.md)

# AuthHandler

[jvm]\
interface [AuthHandler](index.md)

Callback-driven authentication handler.

The library drives the authentication flow per RFC 4252, calling back into this handler for materials. The flow is: none → publickey probe → sign → keyboard-interactive → password

## Functions

| Name | Summary |
|---|---|
| [onAuthMethodsAvailable](on-auth-methods-available.md) | [jvm]<br>open suspend fun [onAuthMethodsAvailable](on-auth-methods-available.md)(methods: [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;)<br>Called when the server reports which authentication methods are available. Override to observe or log. |
| [onBanner](on-banner.md) | [jvm]<br>open suspend fun [onBanner](on-banner.md)(message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html))<br>Called when the server sends an authentication banner (SSH_MSG_USERAUTH_BANNER). This is often used for out-of-band authentication instructions (e.g., a URL to visit). |
| [onKeyboardInteractivePrompt](on-keyboard-interactive-prompt.md) | [jvm]<br>abstract suspend fun [onKeyboardInteractivePrompt](on-keyboard-interactive-prompt.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), instruction: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), prompts: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[KeyboardInteractiveCallback.Prompt](../-keyboard-interactive-callback/-prompt/index.md)&gt;): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;?<br>Called when the server sends keyboard-interactive prompts. Return responses (one per prompt), or null to skip keyboard-interactive. |
| [onPasswordNeeded](on-password-needed.md) | [jvm]<br>abstract suspend fun [onPasswordNeeded](on-password-needed.md)(): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)?<br>Return the password, or null to skip password auth. |
| [onPublicKeysNeeded](on-public-keys-needed.md) | [jvm]<br>abstract suspend fun [onPublicKeysNeeded](on-public-keys-needed.md)(): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AuthPublicKey](../-auth-public-key/index.md)&gt;<br>Return public keys to probe. Empty list skips public key auth. |
| [onSignatureRequest](on-signature-request.md) | [jvm]<br>abstract suspend fun [onSignatureRequest](on-signature-request.md)(key: [AuthPublicKey](../-auth-public-key/index.md), dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?<br>Called only for keys the server accepted (PK_OK). Return the signature over [dataToSign](on-signature-request.md), or null to skip this key. |