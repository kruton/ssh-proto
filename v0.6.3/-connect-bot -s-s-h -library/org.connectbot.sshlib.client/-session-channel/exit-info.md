//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SessionChannel](index.md)/[exitInfo](exit-info.md)

# exitInfo

[jvm]\
open override val [exitInfo](exit-info.md): Deferred&lt;[SessionExit](../../org.connectbot.sshlib/-session-exit/index.md)?&gt;

Completes with how the remote process terminated once the server reports it (RFC 4254 section 6.10), or with null when the channel closes without an `exit-status`/`exit-signal` notification. Servers are not required to send one, so null means unknown, not failure.

Typically awaited after [stdout](../../org.connectbot.sshlib/-ssh-session/stdout.md) reaches end-of-stream on an exec channel to collect the command's exit code.