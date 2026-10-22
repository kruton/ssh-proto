//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[open](open.md)

# open

[jvm]\
abstract suspend fun [open](open.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), flags: [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[SftpOpenFlag](../-sftp-open-flag/index.md)&gt;, attrs: [SftpAttributes](../-sftp-attributes/index.md) = SftpAttributes.EMPTY): [SftpResult](../-sftp-result/index.md)&lt;[SftpFileHandle](../-sftp-file-handle/index.md)&gt;

Open a file. Returns a handle for subsequent read/write/close operations.