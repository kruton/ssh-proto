//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SftpDirectoryEntry](index.md)

# SftpDirectoryEntry

data class [SftpDirectoryEntry](index.md)(val filename: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val longname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val attrs: [SftpAttributes](../-sftp-attributes/index.md))

Entry from an SFTP directory listing.

#### Parameters

jvm

| | |
|---|---|
| filename | Short filename (e.g. &quot;file.txt&quot;) |
| longname | Long-format listing (e.g. &quot;-rw-r--r-- 1 user group 1234 Jan 1 00:00 file.txt&quot;) |
| attrs | File attributes |

## Constructors

| | |
|---|---|
| [SftpDirectoryEntry](-sftp-directory-entry.md) | [jvm]<br>constructor(filename: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), longname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), attrs: [SftpAttributes](../-sftp-attributes/index.md)) |

## Properties

| Name | Summary |
|---|---|
| [attrs](attrs.md) | [jvm]<br>val [attrs](attrs.md): [SftpAttributes](../-sftp-attributes/index.md) |
| [filename](filename.md) | [jvm]<br>val [filename](filename.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [longname](longname.md) | [jvm]<br>val [longname](longname.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |