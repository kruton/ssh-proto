//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[HostKeyVerifier](index.md)/[verify](verify.md)

# verify

[jvm]\
abstract suspend fun [verify](verify.md)(key: [PublicKey](../-public-key/index.md)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Verify the server's host key.

#### Return

true if the key is trusted, false otherwise.

#### Parameters

jvm

| | |
|---|---|
| key | The server's public key. |