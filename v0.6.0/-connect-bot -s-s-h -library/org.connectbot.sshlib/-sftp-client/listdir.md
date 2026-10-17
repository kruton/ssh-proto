//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[listdir](listdir.md)

# listdir

[jvm]\
open suspend fun [listdir](listdir.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[SftpDirectoryEntry](../-sftp-directory-entry/index.md)&gt;&gt;

List all entries in a directory. Convenience method that handles opendir/readdir/close internally.