//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[sftpRequestTimeoutMs](sftp-request-timeout-ms.md)

# sftpRequestTimeoutMs

[jvm]\
var [sftpRequestTimeoutMs](sftp-request-timeout-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)

Default response timeout for ordinary requests on clients opened by [SshClient.openSftp](../../-ssh-client/open-sftp.md). Defaults to 30 seconds; 0 waits until completion, disconnect, or coroutine cancellation. Excludes SFTP version negotiation and request writes. [SftpClient.copyData](../../-sftp-client/copy-data.md) uses its per-call timeout instead.