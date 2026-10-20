//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSession](index.md)/[requestExec](request-exec.md)

# requestExec

[jvm]\
abstract suspend fun [requestExec](request-exec.md)(command: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Request execution of a command on this session channel (RFC 4254 section 6.5).

Only one of [requestShell](request-shell.md), [requestExec](request-exec.md), or subsystem requests may succeed per session channel.

#### Return

true if the server accepted the request

#### Parameters

jvm

| | |
|---|---|
| command | The command to execute on the remote server |