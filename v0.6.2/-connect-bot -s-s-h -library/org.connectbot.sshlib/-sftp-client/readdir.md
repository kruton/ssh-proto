//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[readdir](readdir.md)

# readdir

[jvm]\
abstract suspend fun [readdir](readdir.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md)): [SftpResult](../-sftp-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[SftpDirectoryEntry](../-sftp-directory-entry/index.md)&gt;?&gt;

Read the next batch of directory entries. Returns [SftpResult.Success](../-sftp-result/-success/index.md) with entries, or with null at end of directory.