//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[disconnect](disconnect.md)

# disconnect

[jvm]\
suspend fun [disconnect](disconnect.md)()

Disconnect from the SSH server.

Aborts outstanding writes, discards unread channel output, and closes the transport. Await [SshSession.write](../-ssh-session/write.md) before disconnecting when local write completion matters. To confirm remote processing, wait for the corresponding application or protocol response before disconnecting.