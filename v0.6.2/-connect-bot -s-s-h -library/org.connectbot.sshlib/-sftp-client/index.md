//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)

# SftpClient

[jvm]\
interface [SftpClient](index.md) : [AutoCloseable](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/AutoCloseable.html)

SFTP client for file transfer over SSH (draft-ietf-secsh-filexfer).

Obtain an instance via [SshClient.openSftp](../-ssh-client/open-sftp.md). All methods are suspend functions for use with Kotlin coroutines. Multiple concurrent operations are supported via SFTP request pipelining.

All operations return [SftpResult](../-sftp-result/index.md) instead of throwing exceptions, so errors can be handled structurally. Use [getOrNull](../get-or-null.md) or [getOrThrow](../get-or-throw.md) for convenience.

Usage:

```kotlin
val sftp = client.openSftp() ?: error("Failed to open SFTP")
try {
    when (val result = sftp.listdir("/home/user")) {
        is SftpResult.Success -> result.value.forEach { println(it.filename) }
        is SftpResult.ServerError -> println("Error: ${result.message}")
        is SftpResult.ProtocolError -> println("Protocol error: ${result.message}")
        is SftpResult.IoError -> println("I/O error: ${result.cause}")
    }
} finally {
    sftp.close()
}
```

## Properties

| Name | Summary |
|---|---|
| [extensions](extensions.md) | [jvm]<br>abstract val [extensions](extensions.md): [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;<br>SFTP protocol extensions the server advertised as `extension-name`/`extension-data` pairs trailing its `SSH_FXP_VERSION` reply (draft-ietf-secsh-filexfer-02 section 3). Only the names are kept; extension-specific data (if any) is discarded. |
| [isOpen](is-open.md) | [jvm]<br>abstract val [isOpen](is-open.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Whether this SFTP session is still open. |
| [protocolVersion](protocol-version.md) | [jvm]<br>abstract val [protocolVersion](protocol-version.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)<br>The negotiated SFTP protocol version (typically 3). |

## Functions

| Name | Summary |
|---|---|
| [close](close.md) | [jvm]<br>abstract override fun [close](close.md)()<br>Close this SFTP session and the underlying SSH channel.<br>[jvm]<br>abstract suspend fun [close](close.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Close a file or directory handle. |
| [copyData](copy-data.md) | [jvm]<br>abstract suspend fun [copyData](copy-data.md)(srcHandle: [SftpFileHandle](../-sftp-file-handle/index.md), srcOffset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), length: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), dstHandle: [SftpFileHandle](../-sftp-file-handle/index.md), dstOffset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), timeoutMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) = 0): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Copies [length](copy-data.md) bytes from [srcHandle](copy-data.md) at [srcOffset](copy-data.md) into [dstHandle](copy-data.md) at [dstOffset](copy-data.md), entirely on the server — no data crosses the wire. This is the `"copy-data"` SFTP protocol extension OpenSSH added in 9.0 (April 2022); it lets the server use an efficient server-side copy (e.g. `copy_file_range()` on Linux) instead of the client reading the whole file and writing it back, and works even for accounts restricted to `internal-sftp` with no shell access (where server-side `cp` via SSH exec cannot run at all). |
| [fsetstat](fsetstat.md) | [jvm]<br>abstract suspend fun [fsetstat](fsetstat.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md), attrs: [SftpAttributes](../-sftp-attributes/index.md)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Set attributes of an open file handle. |
| [fstat](fstat.md) | [jvm]<br>abstract suspend fun [fstat](fstat.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md)): [SftpResult](../-sftp-result/index.md)&lt;[SftpAttributes](../-sftp-attributes/index.md)&gt;<br>Get attributes of an open file handle. |
| [listdir](listdir.md) | [jvm]<br>open suspend fun [listdir](listdir.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[SftpDirectoryEntry](../-sftp-directory-entry/index.md)&gt;&gt;<br>List all entries in a directory. Convenience method that handles opendir/readdir/close internally. |
| [lstat](lstat.md) | [jvm]<br>abstract suspend fun [lstat](lstat.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[SftpAttributes](../-sftp-attributes/index.md)&gt;<br>Get file attributes without following symlinks. |
| [mkdir](mkdir.md) | [jvm]<br>abstract suspend fun [mkdir](mkdir.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), attrs: [SftpAttributes](../-sftp-attributes/index.md) = SftpAttributes.EMPTY): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Create a directory. |
| [open](open.md) | [jvm]<br>abstract suspend fun [open](open.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), flags: [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[SftpOpenFlag](../-sftp-open-flag/index.md)&gt;, attrs: [SftpAttributes](../-sftp-attributes/index.md) = SftpAttributes.EMPTY): [SftpResult](../-sftp-result/index.md)&lt;[SftpFileHandle](../-sftp-file-handle/index.md)&gt;<br>Open a file. Returns a handle for subsequent read/write/close operations. |
| [opendir](opendir.md) | [jvm]<br>abstract suspend fun [opendir](opendir.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[SftpFileHandle](../-sftp-file-handle/index.md)&gt;<br>Open a directory for reading. |
| [read](read.md) | [jvm]<br>abstract suspend fun [read](read.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md), offset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), length: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?&gt;<br>Read data from an open file at the given offset. Returns [SftpResult.Success](../-sftp-result/-success/index.md) with data, or with null at EOF. |
| [readdir](readdir.md) | [jvm]<br>abstract suspend fun [readdir](readdir.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md)): [SftpResult](../-sftp-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[SftpDirectoryEntry](../-sftp-directory-entry/index.md)&gt;?&gt;<br>Read the next batch of directory entries. Returns [SftpResult.Success](../-sftp-result/-success/index.md) with entries, or with null at end of directory. |
| [readlink](readlink.md) | [jvm]<br>abstract suspend fun [readlink](readlink.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;<br>Read the target of a symbolic link. |
| [realpath](realpath.md) | [jvm]<br>abstract suspend fun [realpath](realpath.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;<br>Resolve a path to its canonical absolute form. |
| [remove](remove.md) | [jvm]<br>abstract suspend fun [remove](remove.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Delete a file. |
| [rename](rename.md) | [jvm]<br>abstract suspend fun [rename](rename.md)(oldPath: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), newPath: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Rename or move a file. |
| [rmdir](rmdir.md) | [jvm]<br>abstract suspend fun [rmdir](rmdir.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Remove an empty directory. |
| [setstat](setstat.md) | [jvm]<br>abstract suspend fun [setstat](setstat.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), attrs: [SftpAttributes](../-sftp-attributes/index.md)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Set file attributes by path. |
| [stat](stat.md) | [jvm]<br>abstract suspend fun [stat](stat.md)(path: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[SftpAttributes](../-sftp-attributes/index.md)&gt;<br>Get file attributes, following symlinks. |
| [symlink](symlink.md) | [jvm]<br>abstract suspend fun [symlink](symlink.md)(targetPath: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), linkPath: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Create a symbolic link. |
| [write](write.md) | [jvm]<br>abstract suspend fun [write](write.md)(handle: [SftpFileHandle](../-sftp-file-handle/index.md), offset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;<br>Write data to an open file at the given offset. |