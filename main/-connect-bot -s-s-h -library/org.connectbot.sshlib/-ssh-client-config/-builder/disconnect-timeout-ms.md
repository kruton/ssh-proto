//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[disconnectTimeoutMs](disconnect-timeout-ms.md)

# disconnectTimeoutMs

[jvm]\
var [disconnectTimeoutMs](disconnect-timeout-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)

Maximum wait for sending the final disconnect packet during automatic last-channel shutdown or a key-exchange failure. Defaults to 5 seconds; 0 waits until the write completes or the connection is closed explicitly. Explicit [SshClient.disconnect](../../-ssh-client/disconnect.md) always aborts outstanding writes immediately.