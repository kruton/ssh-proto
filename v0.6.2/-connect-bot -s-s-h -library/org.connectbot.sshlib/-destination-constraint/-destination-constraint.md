//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[DestinationConstraint](index.md)/[DestinationConstraint](-destination-constraint.md)

# DestinationConstraint

[jvm]\
constructor(fromHostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), fromKeyspecs: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt;, toUsername: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), toHostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), toHostspecs: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt;)

#### Parameters

jvm

| | |
|---|---|
| fromHostname | Hostname of the previous hop, empty string for the origin machine |
| fromKeyspecs | Host key specs of the previous hop, empty for the origin machine |
| toUsername | Permitted destination username; empty string means any user is allowed |
| toHostname | Destination hostname |
| toHostspecs | Destination host key specs (must be non-empty) |