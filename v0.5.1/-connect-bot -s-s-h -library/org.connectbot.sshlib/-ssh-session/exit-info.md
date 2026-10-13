//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSession](index.md)/[exitInfo](exit-info.md)

# exitInfo

[jvm]\
abstract val [exitInfo](exit-info.md): Deferred&lt;[SessionExit](../-session-exit/index.md)?&gt;

Completes with how the remote process terminated once the server reports it (RFC 4254 section 6.10), or with null when the channel closes without an `exit-status`/`exit-signal` notification. Servers are not required to send one, so null means unknown, not failure.

Typically awaited after [stdout](stdout.md) reaches end-of-stream on an exec channel to collect the command's exit code.