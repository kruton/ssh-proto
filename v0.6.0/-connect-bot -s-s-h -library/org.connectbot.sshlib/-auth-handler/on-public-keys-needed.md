//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthHandler](index.md)/[onPublicKeysNeeded](on-public-keys-needed.md)

# onPublicKeysNeeded

[jvm]\
abstract suspend fun [onPublicKeysNeeded](on-public-keys-needed.md)(): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AuthPublicKey](../-auth-public-key/index.md)&gt;

Return public keys to probe. Empty list skips public key auth.