//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[forwardStream](forward-stream.md)

# forwardStream

[jvm]\
suspend fun [forwardStream](forward-stream.md)(readChannel: ByteReadChannel, writeChannel: ByteWriteChannel, remoteHost: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), remotePort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), originAddr: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = LOCALHOST, originPort: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0): [StreamForwarder](../-stream-forwarder/index.md)?

Forward a pair of streams through an SSH direct-tcpip channel.

Opens a direct-tcpip channel to [remoteHost](forward-stream.md):[remotePort](forward-stream.md) and copies data bidirectionally between the provided Ktor channels and the SSH channel.

#### Return

StreamForwarder handle, or null if the channel could not be opened

#### Parameters

jvm

| | |
|---|---|
| readChannel | Source of data to send through SSH |
| writeChannel | Destination for data received from SSH |
| remoteHost | Remote host to connect to through SSH |
| remotePort | Remote port to connect to through SSH |
| originAddr | Originator address reported to the server |
| originPort | Originator port reported to the server |