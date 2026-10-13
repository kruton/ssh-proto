//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[sessionWindowSize](session-window-size.md)

# sessionWindowSize

[jvm]\
var [sessionWindowSize](session-window-size.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)

Receive window, in bytes, for shells, commands and manually opened subsystems. SFTP channels opened by [SshClient.openSftp](../../-ssh-client/open-sftp.md) use [sftpWindowSize](sftp-window-size.md). A channel moves at most one window of data per network round trip, so a larger window speeds up bulk transfers on slower links. Each channel may buffer up to this much unread data. Default: 2 MiB. Reduce this for sessions with tighter memory limits.