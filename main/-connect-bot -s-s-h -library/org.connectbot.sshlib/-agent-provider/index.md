//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentProvider](index.md)

# AgentProvider

[jvm]\
interface [AgentProvider](index.md)

Provider interface for SSH agent forwarding.

Implement this interface to handle agent requests from remote servers when agent forwarding is enabled. The library will call these methods when a remote server requests identities or signatures. Implementations should return [AgentResult.Failure](../-agent-result/-failure/index.md) instead of throwing when a backend operation fails.

## Functions

| Name | Summary |
|---|---|
| [addIdentity](add-identity.md) | [jvm]<br>open suspend fun [addIdentity](add-identity.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), comment: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), confirmUse: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html), lifetimeSeconds: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)?): [AgentResult](../-agent-result/index.md)&lt;[Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)&gt;<br>Optional agent management operations. Providers deny mutations by default. |
| [getIdentities](get-identities.md) | [jvm]<br>abstract suspend fun [getIdentities](get-identities.md)(): [AgentResult](../-agent-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentIdentity](../-agent-identity/index.md)&gt;&gt;<br>Return the list of identities available for forwarding. |
| [isLocked](is-locked.md) | [jvm]<br>open suspend fun [isLocked](is-locked.md)(): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Lock state is shared by all forwarded channels using this provider. |
| [lock](lock.md) | [jvm]<br>open suspend fun [lock](lock.md)(passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AgentResult](../-agent-result/index.md)&lt;[Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)&gt; |
| [removeAllIdentities](remove-all-identities.md) | [jvm]<br>open suspend fun [removeAllIdentities](remove-all-identities.md)(): [AgentResult](../-agent-result/index.md)&lt;[Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)&gt; |
| [removeIdentity](remove-identity.md) | [jvm]<br>open suspend fun [removeIdentity](remove-identity.md)(publicKeyBlob: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [AgentResult](../-agent-result/index.md)&lt;[Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)&gt; |
| [signData](sign-data.md) | [jvm]<br>abstract suspend fun [signData](sign-data.md)(context: [AgentSigningContext](../-agent-signing-context/index.md)): [AgentResult](../-agent-result/index.md)&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?&gt;<br>Sign data with the specified key. |
| [unlock](unlock.md) | [jvm]<br>open suspend fun [unlock](unlock.md)(passphrase: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [AgentResult](../-agent-result/index.md)&lt;[Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)&gt; |