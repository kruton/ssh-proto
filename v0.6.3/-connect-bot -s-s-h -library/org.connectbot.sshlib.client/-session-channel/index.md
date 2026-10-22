//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SessionChannel](index.md)

# SessionChannel

[jvm]\
class [SessionChannel](index.md) : [SshSession](../../org.connectbot.sshlib/-ssh-session/index.md)

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [exitInfo](exit-info.md) | [jvm]<br>open override val [exitInfo](exit-info.md): Deferred&lt;[SessionExit](../../org.connectbot.sshlib/-session-exit/index.md)?&gt;<br>Completes with how the remote process terminated once the server reports it (RFC 4254 section 6.10), or with null when the channel closes without an `exit-status`/`exit-signal` notification. Servers are not required to send one, so null means unknown, not failure. |
| [isOpen](is-open.md) | [jvm]<br>open override val [isOpen](is-open.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [localChannelNumber](local-channel-number.md) | [jvm]<br>open override val [localChannelNumber](local-channel-number.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [remoteChannelNumber](remote-channel-number.md) | [jvm]<br>open override val [remoteChannelNumber](remote-channel-number.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) |
| [stderr](stderr.md) | [jvm]<br>open override val [stderr](stderr.md): ReceiveChannel&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt;<br>Standard error, with the same drain and explicit-close contract as [stdout](../../org.connectbot.sshlib/-ssh-session/stdout.md). |
| [stdout](stdout.md) | [jvm]<br>open override val [stdout](stdout.md): ReceiveChannel&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt;<br>Standard output. Data received before remote channel close remains readable through automatic connection teardown. Explicit session close or client disconnect discards it. |

## Functions

| Name | Summary |
|---|---|
| [close](close.md) | [jvm]<br>open override fun [close](close.md)()<br>Discard unread output and release delivery resources, including after remote close. |
| [read](read.md) | [jvm]<br>open suspend override fun [read](read.md)(): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)? |
| [readExtended](read-extended.md) | [jvm]<br>open suspend override fun [readExtended](read-extended.md)(): [Pair](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-pair/index.html)&lt;[Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)&gt;?<br>Read non-stderr extended data. RFC 4254 data type 1 is exposed exclusively through [stderr](../../org.connectbot.sshlib/-ssh-session/stderr.md) so the same remote bytes are not buffered twice. |
| [requestEnv](request-env.md) | [jvm]<br>open suspend override fun [requestEnv](request-env.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), value: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Request an environment variable for this session (RFC 4254 section 6.4). Call before requesting a shell, command, or subsystem. Servers may restrict names (OpenSSH uses AcceptEnv) and reject requests after process startup. Names and values are encoded as UTF-8. Returns false for NUL-containing input, a closed channel, or server rejection; rejection does not close the session. |
| [requestExec](request-exec.md) | [jvm]<br>open suspend override fun [requestExec](request-exec.md)(command: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Request execution of a command on this session channel (RFC 4254 section 6.5). |
| [requestPty](request-pty.md) | [jvm]<br>open suspend override fun [requestPty](request-pty.md)(terminalType: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;xterm&quot;, widthChars: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 80, heightRows: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 24, widthPixels: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0, heightPixels: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 0, terminalModes: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html) = byteArrayOf(0)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [requestShell](request-shell.md) | [jvm]<br>open suspend override fun [requestShell](request-shell.md)(): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [requestSubsystem](request-subsystem.md) | [jvm]<br>open suspend override fun [requestSubsystem](request-subsystem.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Request a subsystem on this session channel (RFC 4254 section 6.5). |
| [resizeTerminal](resize-terminal.md) | [jvm]<br>open suspend override fun [resizeTerminal](resize-terminal.md)(widthChars: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), heightRows: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), widthPixels: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), heightPixels: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) |
| [sendEof](send-eof.md) | [jvm]<br>open suspend override fun [sendEof](send-eof.md)() |
| [write](write.md) | [jvm]<br>open suspend override fun [write](write.md)(data: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html))<br>Write data, suspending for channel window credit and transport backpressure. |