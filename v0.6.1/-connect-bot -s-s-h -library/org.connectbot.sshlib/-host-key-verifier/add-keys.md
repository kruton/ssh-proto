//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[HostKeyVerifier](index.md)/[addKeys](add-keys.md)

# addKeys

[jvm]\
open suspend fun [addKeys](add-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;)

Persist the supported keys advertised by an authenticated server after every requested proof of private-key possession has been verified. Runs outside packet routing. Read-only verifiers may keep the default implementation.