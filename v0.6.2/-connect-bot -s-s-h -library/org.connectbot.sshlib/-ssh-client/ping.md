//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshClient](index.md)/[ping](ping.md)

# ping

[jvm]\
suspend fun [ping](ping.md)(): [PingResult](../-ping-result/index.md)

Send an SSH ping to the server and return the round-trip time.

Requires a prior successful [connect](connect.md) and authentication. Returns [PingResult.NotAuthenticated](../-ping-result/-not-authenticated/index.md) if there is no active connection or authentication has not completed, [PingResult.NotSupported](../-ping-result/-not-supported/index.md) if the server did not advertise `ping@openssh.com` support via SSH2_MSG_EXT_INFO, or [PingResult.Failure](../-ping-result/-failure/index.md) if the ping cannot be sent or the connection closes before the server replies.

#### Return

[PingResult.Success](../-ping-result/-success/index.md) with round-trip nanoseconds, [PingResult.NotSupported](../-ping-result/-not-supported/index.md), [PingResult.NotAuthenticated](../-ping-result/-not-authenticated/index.md), or [PingResult.Failure](../-ping-result/-failure/index.md)