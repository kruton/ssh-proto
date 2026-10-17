//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[sftpWindowSize](sftp-window-size.md)

# sftpWindowSize

[jvm]\
var [sftpWindowSize](sftp-window-size.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)

Receive window, in bytes, for channels opened by [SshClient.openSftp](../../-ssh-client/open-sftp.md). Default: 8 MiB, to sustain bulk downloads on higher-latency links. Each channel may buffer up to this much unread data; reduce this for tighter memory limits.