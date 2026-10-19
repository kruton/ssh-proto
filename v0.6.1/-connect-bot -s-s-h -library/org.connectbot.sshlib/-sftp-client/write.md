//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[write](write.md)

# write

[jvm]\
abstract suspend fun [write](write.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md), offset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;

Write data to an open file at the given offset.