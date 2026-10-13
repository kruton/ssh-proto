//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentProvider](index.md)/[getIdentities](get-identities.md)

# getIdentities

[jvm]\
abstract suspend fun [getIdentities](get-identities.md)(): [AgentResult](../-agent-result/index.md)&lt;[List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentIdentity](../-agent-identity/index.md)&gt;&gt;

Return the list of identities available for forwarding.

Called when a remote server requests the list of available keys. Return [AgentResult.Failure](../-agent-result/-failure/index.md) if the identities cannot be loaded.