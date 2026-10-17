//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)

# Builder

[jvm]\
class [Builder](index.md)

## Constructors

| | |
|---|---|
| [Builder](-builder.md) | [jvm]<br>constructor() |

## Properties

| Name | Summary |
|---|---|
| [autoDisconnectOnLastChannelClose](auto-disconnect-on-last-channel-close.md) | [jvm]<br>var [autoDisconnectOnLastChannelClose](auto-disconnect-on-last-channel-close.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Whether to automatically disconnect the SSH connection when the last channel is closed. |
| [clientVersion](client-version.md) | [jvm]<br>var [clientVersion](client-version.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>Client version string sent during SSH handshake. |
| [enableCompression](enable-compression.md) | [jvm]<br>var [enableCompression](enable-compression.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Enable zlib compression. When true, the client offers `zlib@openssh.com,zlib,none`; when false, only `none`. |
| [encryptionAlgorithms](encryption-algorithms.md) | [jvm]<br>var [encryptionAlgorithms](encryption-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [environment](environment.md) | [jvm]<br>var [environment](environment.md): [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;<br>Environment variables sent before each session starts, including SFTP. Servers may ignore variables not allowed by their policy (OpenSSH AcceptEnv). Names and values use UTF-8 and must not contain NUL. Only supplied variables are sent. |
| [host](host.md) | [jvm]<br>var [host](host.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>Hostname for TCP connections. Used with default KtorTcpTransport. Ignored if [transportFactory](transport-factory.md) is set explicitly. |
| [hostKeyAlgorithms](host-key-algorithms.md) | [jvm]<br>var [hostKeyAlgorithms](host-key-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [hostKeyVerifier](host-key-verifier.md) | [jvm]<br>var [hostKeyVerifier](host-key-verifier.md): [HostKeyVerifier](../../-host-key-verifier/index.md)?<br>Host key verifier. |
| [ipVersion](ip-version.md) | [jvm]<br>var [ipVersion](ip-version.md): [IpVersion](../../../org.connectbot.sshlib.transport/-ip-version/index.md)<br>IP version preference for the default TCP transport. Ignored if [transportFactory](transport-factory.md) is set explicitly. |
| [keepAliveIntervalMs](keep-alive-interval-ms.md) | [jvm]<br>var [keepAliveIntervalMs](keep-alive-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)<br>Send an SSH_MSG_IGNORE heartbeat every N milliseconds to keep the connection alive across NAT/VPN/firewall idle timeouts. |
| [kexAlgorithms](kex-algorithms.md) | [jvm]<br>var [kexAlgorithms](kex-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [macAlgorithms](mac-algorithms.md) | [jvm]<br>var [macAlgorithms](mac-algorithms.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [obscureKeystrokeTimingIntervalMs](obscure-keystroke-timing-interval-ms.md) | [jvm]<br>var [obscureKeystrokeTimingIntervalMs](obscure-keystroke-timing-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)<br>Quantize outbound keystroke packet timing to this interval (milliseconds) to mask inter-keystroke timing patterns. Requires a PTY session and server support for `ping@openssh.com`. Set to 0 to disable. |
| [port](port.md) | [jvm]<br>var [port](port.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)<br>Port for TCP connections. Used with default KtorTcpTransport. Ignored if [transportFactory](transport-factory.md) is set explicitly. |
| [preferPasswordAuth](prefer-password-auth.md) | [jvm]<br>var [preferPasswordAuth](prefer-password-auth.md): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>When true, prefer `password` over `keyboard-interactive` when both are available. By default, `keyboard-interactive` is preferred. |
| [rekeyBytesLimit](rekey-bytes-limit.md) | [jvm]<br>var [rekeyBytesLimit](rekey-bytes-limit.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)<br>Re-key after this many wire bytes (sent or received). Default: 1 GB. |
| [rekeyIntervalMs](rekey-interval-ms.md) | [jvm]<br>var [rekeyIntervalMs](rekey-interval-ms.md): [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)<br>Re-key after this many milliseconds. Default: 1 hour. |
| [sessionWindowSize](session-window-size.md) | [jvm]<br>var [sessionWindowSize](session-window-size.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)<br>Receive window, in bytes, for shells, commands and manually opened subsystems. SFTP channels opened by [SshClient.openSftp](../../-ssh-client/open-sftp.md) use [sftpWindowSize](sftp-window-size.md). A channel moves at most one window of data per network round trip, so a larger window speeds up bulk transfers on slower links. Each channel may buffer up to this much unread data. Default: 2 MiB. Reduce this for sessions with tighter memory limits. |
| [sftpWindowSize](sftp-window-size.md) | [jvm]<br>var [sftpWindowSize](sftp-window-size.md): [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html)<br>Receive window, in bytes, for channels opened by [SshClient.openSftp](../../-ssh-client/open-sftp.md). Default: 8 MiB, to sustain bulk downloads on higher-latency links. Each channel may buffer up to this much unread data; reduce this for tighter memory limits. |
| [transportFactory](transport-factory.md) | [jvm]<br>var [transportFactory](transport-factory.md): [TransportFactory](../../../org.connectbot.sshlib.transport/-transport-factory/index.md)?<br>Custom transport factory. If not set, uses [KtorTcpTransportFactory](../../../org.connectbot.sshlib.transport/-ktor-tcp-transport-factory/index.md) with [host](host.md), [port](port.md), and [ipVersion](ip-version.md). |

## Functions

| Name | Summary |
|---|---|
| [build](build.md) | [jvm]<br>fun [build](build.md)(): [SshClientConfig](../index.md) |