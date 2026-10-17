//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SshConnection](index.md)/[openSessionChannel](open-session-channel.md)

# openSessionChannel

[jvm]\
suspend fun [openSessionChannel](open-session-channel.md)(initialWindowSize: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = sessionWindowSize, maxPacketSize: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 32 * 1024): [SessionChannel](../-session-channel/index.md)?

Open a session channel (RFC 4254 section 6.1).

#### Return

SessionChannel instance if successful, null otherwise