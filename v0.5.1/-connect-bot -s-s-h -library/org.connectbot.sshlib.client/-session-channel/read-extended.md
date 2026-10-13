//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SessionChannel](index.md)/[readExtended](read-extended.md)

# readExtended

[jvm]\
open suspend override fun [readExtended](read-extended.md)(): [Pair](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-pair/index.html)&lt;[Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt;?

Read non-stderr extended data. RFC 4254 data type 1 is exposed exclusively through [stderr](../../org.connectbot.sshlib/-ssh-session/stderr.md) so the same remote bytes are not buffered twice.