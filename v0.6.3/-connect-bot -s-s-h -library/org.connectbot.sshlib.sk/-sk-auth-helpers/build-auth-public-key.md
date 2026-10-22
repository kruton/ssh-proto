//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.sk](../index.md)/[SkAuthHelpers](index.md)/[buildAuthPublicKey](build-auth-public-key.md)

# buildAuthPublicKey

[jvm]\
fun [buildAuthPublicKey](build-auth-public-key.md)(algorithm: [SkAlgorithm](../-sk-algorithm/index.md), rawKey: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html), application: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AuthPublicKey](../../org.connectbot.sshlib/-auth-public-key/index.md)

Build an [AuthPublicKey](../../org.connectbot.sshlib/-auth-public-key/index.md) for an SK credential, suitable for returning from [org.connectbot.sshlib.AuthHandler.onPublicKeysNeeded](../../org.connectbot.sshlib/-auth-handler/on-public-keys-needed.md).

The public-key blob is encoded per [SkPublicKeyEncoder](../-sk-public-key-encoder/index.md).