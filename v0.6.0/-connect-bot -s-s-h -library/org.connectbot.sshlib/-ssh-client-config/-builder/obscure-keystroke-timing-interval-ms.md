//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[obscureKeystrokeTimingIntervalMs](obscure-keystroke-timing-interval-ms.md)

# obscureKeystrokeTimingIntervalMs

[jvm]\
var [obscureKeystrokeTimingIntervalMs](obscure-keystroke-timing-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)

Quantize outbound keystroke packet timing to this interval (milliseconds) to mask inter-keystroke timing patterns. Requires a PTY session and server support for `ping@openssh.com`. Set to 0 to disable.