//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[openSftp](open-sftp.md)

# openSftp

[jvm]\
suspend fun [openSftp](open-sftp.md)(): [SftpResult](../-sftp-result/index.md)&lt;[SftpClient](../-sftp-client/index.md)&gt;

Open an SFTP session for file transfer.

Opens a new session channel, starts the &quot;sftp&quot; subsystem, and performs SFTP version negotiation.

#### Return

[SftpResult.Success](../-sftp-result/-success/index.md) with the client, or an error variant