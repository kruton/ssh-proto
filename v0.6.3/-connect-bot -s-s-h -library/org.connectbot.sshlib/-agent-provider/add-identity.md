//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AgentProvider](index.md)/[addIdentity](add-identity.md)

# addIdentity

[jvm]\
open suspend fun [addIdentity](add-identity.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), comment: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), confirmUse: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html), lifetimeSeconds: [Long](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-long/index.html)?): [AgentResult](../-agent-result/index.md)&lt;[Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)&gt;

Optional agent management operations. Providers deny mutations by default.