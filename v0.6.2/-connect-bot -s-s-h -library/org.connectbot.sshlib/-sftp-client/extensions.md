//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpClient](index.md)/[extensions](extensions.md)

# extensions

[jvm]\
abstract val [extensions](extensions.md): [Set](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-set/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;

SFTP protocol extensions the server advertised as `extension-name`/`extension-data` pairs trailing its `SSH_FXP_VERSION` reply (draft-ietf-secsh-filexfer-02 section 3). Only the names are kept; extension-specific data (if any) is discarded.

Common OpenSSH extensions found here: `"copy-data"` (see [copyData](copy-data.md)), `"posix-rename@openssh.com"`, `"hardlink@openssh.com"`, `"fsync@openssh.com"`, `"statvfs@openssh.com"`. Empty if the server advertised none (or a server this old predates extensions entirely).