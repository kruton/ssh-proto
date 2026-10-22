//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[read](read.md)

# read

[jvm]\
abstract suspend fun [read](read.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md), offset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), length: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?&gt;

Read data from an open file at the given offset. Returns [SftpResult.Success](../-sftp-result/-success/index.md) with data, or with null at EOF.