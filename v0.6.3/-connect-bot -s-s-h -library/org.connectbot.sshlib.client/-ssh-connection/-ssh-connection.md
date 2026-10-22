//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib.client](../index.md)/[SshConnection](index.md)/[SshConnection](-ssh-connection.md)

# SshConnection

[jvm]\
constructor(transport: [Transport](../../org.connectbot.sshlib.transport/-transport/index.md), clientVersion: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = &quot;SSH-2.0-CBSSH_1.0&quot;, hostKeyVerifier: [HostKeyVerifier](../../org.connectbot.sshlib/-host-key-verifier/index.md), kexAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = KexEntry.defaultString, hostKeyAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = SignatureEntry.defaultString, encryptionAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = CipherEntry.defaultString, macAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = MacEntry.defaultString, compressionAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) = CompressionEntry.defaultString, preferPasswordAuth: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html) = false, rekeyIntervalMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), rekeyBytesLimit: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html), obscureKeystrokeTimingIntervalMs: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html) = 20, coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO, pubkeyAlgorithms: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null, cryptoPolicy: [SshCryptoPolicy](../../org.connectbot.sshlib/-ssh-crypto-policy/index.md)? = null, onAlgorithmWarning: ([AlgorithmPolicyWarning](../../org.connectbot.sshlib/-algorithm-policy-warning/index.md)) -&gt; [Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html) = {})

#### Parameters

jvm

| | |
|---|---|
| transport | Underlying transport (e.g., TCP socket) |
| clientVersion | Client version string (default: SSH-2.0-CBSSH_1.0) |