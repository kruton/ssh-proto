//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshCertificate](../index.md)/[Companion](index.md)

# Companion

[jvm]\
object [Companion](index.md)

## Functions

| Name | Summary |
|---|---|
| [decode](decode.md) | [jvm]<br>@[JvmStatic](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-static/index.html)<br>fun [decode](decode.md)(encoded: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SshCertificate](../index.md)<br>Decode a complete SSH wire-format certificate blob.<br>[jvm]<br>@[JvmStatic](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-static/index.html)<br>fun [decode](decode.md)(text: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [SshCertificate](../index.md)<br>Decode an OpenSSH certificate line, as produced in a `-cert.pub` file. |