//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[copyData](copy-data.md)

# copyData

[jvm]\
abstract suspend fun [copyData](copy-data.md)(srcHandle: [SftpFileHandle](../-sftp-file-handle/index.md), srcOffset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), length: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), dstHandle: [SftpFileHandle](../-sftp-file-handle/index.md), dstOffset: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), timeoutMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) = 0): [SftpResult](../-sftp-result/index.md)&lt;[Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html)&gt;

Copies [length](copy-data.md) bytes from [srcHandle](copy-data.md) at [srcOffset](copy-data.md) into [dstHandle](copy-data.md) at [dstOffset](copy-data.md), entirely on the server — no data crosses the wire. This is the `"copy-data"` SFTP protocol extension OpenSSH added in 9.0 (April 2022); it lets the server use an efficient server-side copy (e.g. `copy_file_range()` on Linux) instead of the client reading the whole file and writing it back, and works even for accounts restricted to `internal-sftp` with no shell access (where server-side `cp` via SSH exec cannot run at all).

Both handles must already be open ([open](open.md) with [SftpOpenFlag.READ](../-sftp-open-flag/-r-e-a-d/index.md) for [srcHandle](copy-data.md), [SftpOpenFlag.WRITE](../-sftp-open-flag/-w-r-i-t-e/index.md) for [dstHandle](copy-data.md)) — this call does not open, create, or close anything. Only regular files are supported; there is no protocol-level operation for copying whole directory trees, so recursive copies still need to be driven by the caller (walk the tree, `mkdir` each directory, `copyData` each regular file).

Check [extensions](extensions.md) for `"copy-data"` before calling, or be prepared to fall back on an [SftpResult.ServerError](../-sftp-result/-server-error/index.md) with [SftpStatusCode.OP_UNSUPPORTED](../-sftp-status-code/-o-p_-u-n-s-u-p-p-o-r-t-e-d/index.md) — older or non-OpenSSH servers may not implement this extension at all.

#### Parameters

jvm

| | |
|---|---|
| length | Number of bytes to copy; `0` means &quot;copy through EOF of the source file&quot;. |
| timeoutMs | Maximum time to wait for the server response; `0` (default) waits until completion or disconnect. The caller may also cancel the coroutine. A timeout or cancellation stops waiting but does not cancel the copy on the server. |