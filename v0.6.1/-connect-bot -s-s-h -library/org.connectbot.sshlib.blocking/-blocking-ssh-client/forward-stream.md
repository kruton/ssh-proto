//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.blocking](../index.md)/[BlockingSshClient](index.md)/[forwardStream](forward-stream.md)

# forwardStream

[jvm]\

@[JvmOverloads](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.jvm/-jvm-overloads/index.html)

fun [forwardStream](forward-stream.md)(readChannel: ByteReadChannel, writeChannel: ByteWriteChannel, remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;127.0.0.1&quot;, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [StreamForwarder](../../org.connectbot.sshlib/-stream-forwarder/index.md)?

Forward Ktor byte channels through an SSH direct-tcpip channel.