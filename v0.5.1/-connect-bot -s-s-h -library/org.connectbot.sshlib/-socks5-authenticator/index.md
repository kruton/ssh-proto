//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[Socks5Authenticator](index.md)

# Socks5Authenticator

[jvm]\
interface [Socks5Authenticator](index.md)

Authenticator for SOCKS5 username/password auth (RFC 1929).

Implement this to validate credentials for dynamic port forwarding.

## Functions

| Name | Summary |
|---|---|
| [authenticate](authenticate.md) | [jvm]<br>abstract fun [authenticate](authenticate.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |