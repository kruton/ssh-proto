//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshCertificate](../index.md)/[Companion](index.md)/[decode](decode.md)

# decode

[jvm]\

@[JvmStatic](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-static/index.html)

fun [decode](decode.md)(text: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SshCertificate](../index.md)

Decode an OpenSSH certificate line, as produced in a `-cert.pub` file.

[jvm]\

@[JvmStatic](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-static/index.html)

fun [decode](decode.md)(encoded: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SshCertificate](../index.md)

Decode a complete SSH wire-format certificate blob.