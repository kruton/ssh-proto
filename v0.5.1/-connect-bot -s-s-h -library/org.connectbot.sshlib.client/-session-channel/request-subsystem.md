//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SessionChannel](index.md)/[requestSubsystem](request-subsystem.md)

# requestSubsystem

[jvm]\
open suspend override fun [requestSubsystem](request-subsystem.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Request a subsystem on this session channel (RFC 4254 section 6.5).

Subsystems are named services that run over an SSH channel, such as SFTP (&quot;sftp&quot;). Only one of [requestShell](../../org.connectbot.sshlib/-ssh-session/request-shell.md), exec, or [requestSubsystem](../../org.connectbot.sshlib/-ssh-session/request-subsystem.md) may succeed per session channel.

#### Return

true if the server accepted the request

#### Parameters

jvm

| | |
|---|---|
| name | The subsystem name (e.g. &quot;sftp&quot;) |