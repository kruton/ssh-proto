//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[HostKeyVerifier](index.md)

# HostKeyVerifier

interface [HostKeyVerifier](index.md)

Verifies the identity of a server by checking its host key.

Implementations of this interface determine whether a server's host key is trusted. This is typically done by consulting a `known_hosts` database.

#### Inheritors

| |
|---|
| [KnownHostsVerifier](../-known-hosts-verifier/index.md) |

## Functions

| Name | Summary |
|---|---|
| [addKeys](add-keys.md) | [jvm]<br>open suspend fun [addKeys](add-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;) |
| [removeKeys](remove-keys.md) | [jvm]<br>open suspend fun [removeKeys](remove-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;) |
| [verify](verify.md) | [jvm]<br>abstract suspend fun [verify](verify.md)(key: [PublicKey](../-public-key/index.md)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Verify the server's host key. |