//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshKeyRevocationList](../index.md)/[Companion](index.md)/[decode](decode.md)

# decode

[jvm]\

@[JvmStatic](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-static/index.html)

fun [decode](decode.md)(encoded: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [SshKeyRevocationList](../index.md)

Decode a complete KRL. Malformed or unsupported lists throw; they never become empty lists.