//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[hostKeyUpdateTimeoutMs](host-key-update-timeout-ms.md)

# hostKeyUpdateTimeoutMs

[jvm]\
var [hostKeyUpdateTimeoutMs](host-key-update-timeout-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)

Timeout for processing a server's host-key update, including proof requests and verifier persistence callbacks. Defaults to 30 seconds; 0 waits until completion or connection shutdown. Failed or timed-out updates do not replace trusted keys unless their proofs have been verified.