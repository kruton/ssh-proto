//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[HostKeyVerifier](index.md)/[removeKeys](remove-keys.md)

# removeKeys

[jvm]\
open suspend fun [removeKeys](remove-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;)

Retire the authenticated key when omitted from the advertisement, after [addKeys](add-keys.md) returns successfully. Other stored keys are not enumerated or removed.