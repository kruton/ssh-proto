//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[handshakeTimeoutMs](handshake-timeout-ms.md)

# handshakeTimeoutMs

[jvm]\
var [handshakeTimeoutMs](handshake-timeout-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)

Maximum wait for initial key exchange and service negotiation after version exchange, including host-key verification. Does not limit TCP connection, version exchange, authentication, or reads from an established session.

Defaults to 30 seconds. Set to 0 to wait until completion, transport failure, or coroutine cancellation, for example when an interactive user may take time to approve a host key or the server performs slow DH calculations.