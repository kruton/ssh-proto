//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSession](index.md)/[write](write.md)

# write

[jvm]\
abstract suspend fun [write](write.md)(data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))

Write data, suspending for channel window credit and transport backpressure.

Successful completion means the transport writes completed, not that the remote application processed the data. Await an application response when that confirmation is required. Disconnecting the client can abort a suspended write.