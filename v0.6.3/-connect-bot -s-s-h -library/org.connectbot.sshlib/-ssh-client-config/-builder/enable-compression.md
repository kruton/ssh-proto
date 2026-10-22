//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[enableCompression](enable-compression.md)

# enableCompression

[jvm]\
var [enableCompression](enable-compression.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Enable zlib compression. When true, the client offers `zlib@openssh.com,zlib,none`; when false, only `none`.