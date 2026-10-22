//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshKeyRevocationList](index.md)

# SshKeyRevocationList

[jvm]\
class [SshKeyRevocationList](index.md)

An immutable OpenSSH KRL v1 loaded through an application-trusted channel.

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Functions

| Name | Summary |
|---|---|
| [isRevoked](is-revoked.md) | [jvm]<br>fun [isRevoked](is-revoked.md)(key: [PublicKey](../-public-key/index.md)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Check a raw key or certificate, including revocation of its certified key or CA. |