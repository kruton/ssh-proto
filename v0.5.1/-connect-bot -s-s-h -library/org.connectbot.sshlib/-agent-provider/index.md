//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentProvider](index.md)

# AgentProvider

[jvm]\
interface [AgentProvider](index.md)

Provider interface for SSH agent forwarding.

Implement this interface to handle agent requests from remote servers when agent forwarding is enabled. The library will call these methods when a remote server requests identities or signatures. Implementations should return [AgentResult.Failure](../-agent-result/-failure/index.md) instead of throwing when a backend operation fails.

## Functions

| Name | Summary |
|---|---|
| [getIdentities](get-identities.md) | [jvm]<br>abstract suspend fun [getIdentities](get-identities.md)(): [AgentResult](../-agent-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentIdentity](../-agent-identity/index.md)&gt;&gt;<br>Return the list of identities available for forwarding. |
| [signData](sign-data.md) | [jvm]<br>abstract suspend fun [signData](sign-data.md)(context: [AgentSigningContext](../-agent-signing-context/index.md)): [AgentResult](../-agent-result/index.md)&lt;[ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?&gt;<br>Sign data with the specified key. |