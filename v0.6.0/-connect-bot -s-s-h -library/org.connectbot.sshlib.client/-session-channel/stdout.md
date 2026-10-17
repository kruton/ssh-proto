//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SessionChannel](index.md)/[stdout](stdout.md)

# stdout

[jvm]\
open override val [stdout](stdout.md): ReceiveChannel&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt;

Standard output. Data received before remote channel close remains readable through automatic connection teardown. Explicit session close or client disconnect discards it.