//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SshConnection](index.md)

# SshConnection

class [SshConnection](index.md)(transport: [Transport](../../org.connectbot.sshlib.transport/-transport/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;, hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), kexAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = KexEntry.defaultString, hostKeyAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = SignatureEntry.defaultString, encryptionAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = CipherEntry.defaultString, macAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = MacEntry.defaultString, compressionAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = CompressionEntry.defaultString, preferPasswordAuth: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) = false, rekeyIntervalMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), rekeyBytesLimit: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), obscureKeystrokeTimingIntervalMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) = 20, coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO)

SSH connection handler that manages the protocol flow.

This class ties together the state machine, transport layer, and crypto implementations to handle a complete SSH connection lifecycle.

#### Parameters

jvm

| | |
|---|---|
| transport | Underlying transport (e.g., TCP socket) |
| clientVersion | Client version string (default: SSH-2.0-CBSSH_1.0) |

## Constructors

| | |
|---|---|
| [SshConnection](-ssh-connection.md) | [jvm]<br>constructor(transport: [Transport](../../org.connectbot.sshlib.transport/-transport/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;, hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), kexAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = KexEntry.defaultString, hostKeyAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = SignatureEntry.defaultString, encryptionAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = CipherEntry.defaultString, macAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = MacEntry.defaultString, compressionAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = CompressionEntry.defaultString, preferPasswordAuth: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) = false, rekeyIntervalMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), rekeyBytesLimit: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), obscureKeystrokeTimingIntervalMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) = 20, coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO) |

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [jvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [disconnectedFlow](disconnected-flow.md) | [jvm]<br>val [disconnectedFlow](disconnected-flow.md): SharedFlow&lt;[Throwable](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-throwable/index.html)?&gt; |

## Functions

| Name | Summary |
|---|---|
| [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md) | [jvm]<br>suspend fun [authenticateKeyboardInteractive](authenticate-keyboard-interactive.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), callback: [KeyboardInteractiveCallback](../../org.connectbot.sshlib/-keyboard-interactive-callback/index.md)): [AuthResult](../../org.connectbot.sshlib/-auth-result/index.md)<br>Authenticate using keyboard-interactive (RFC 4256). |
| [authenticatePassword](authenticate-password.md) | [jvm]<br>suspend fun [authenticatePassword](authenticate-password.md)(username: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AuthResult](../../org.connectbot.sshlib/-auth-result/index.md)<br>Authenticate using password. |
| [close](close.md) | [jvm]<br>suspend fun [close](close.md)() |
| [connect](connect.md) | [jvm]<br>suspend fun [connect](connect.md)(): [ConnectResult](../../org.connectbot.sshlib/-connect-result/index.md)<br>Initiate SSH connection. Performs SSH version exchange, key exchange, and service negotiation. Returns [ConnectResult.Success](../../org.connectbot.sshlib/-connect-result/-success/index.md) when the transport is ready for authentication calls. |
| [enableAgentForwarding](enable-agent-forwarding.md) | [jvm]<br>fun [enableAgentForwarding](enable-agent-forwarding.md)(provider: [AgentProvider](../../org.connectbot.sshlib/-agent-provider/index.md))<br>Enable SSH agent forwarding with the provided agent. |
| [openSessionChannel](open-session-channel.md) | [jvm]<br>suspend fun [openSessionChannel](open-session-channel.md)(initialWindowSize: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = sessionWindowSize, maxPacketSize: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 32 * 1024): [SessionChannel](../-session-channel/index.md)?<br>Open a session channel (RFC 4254 section 6.1). |