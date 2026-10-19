//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[DestinationConstraint](index.md)

# DestinationConstraint

data class [DestinationConstraint](index.md)(val fromHostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val fromKeyspecs: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt;, val toUsername: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val toHostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val toHostspecs: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt;)

One hop entry in a destination constraint for a key in the agent.

Describes a single permitted (from → to) hop in a forwarding chain. When fromHostname and fromKeyspecs are empty this is an origin-direct constraint (key may be used directly from the machine running the agent).

#### Parameters

jvm

| | |
|---|---|
| fromHostname | Hostname of the previous hop, empty string for the origin machine |
| fromKeyspecs | Host key specs of the previous hop, empty for the origin machine |
| toUsername | Permitted destination username; empty string means any user is allowed |
| toHostname | Destination hostname |
| toHostspecs | Destination host key specs (must be non-empty) |

## Constructors

| | |
|---|---|
| [DestinationConstraint](-destination-constraint.md) | [jvm]<br>constructor(fromHostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), fromKeyspecs: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt;, toUsername: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), toHostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), toHostspecs: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt;) |

## Properties

| Name | Summary |
|---|---|
| [fromHostname](from-hostname.md) | [jvm]<br>val [fromHostname](from-hostname.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [fromKeyspecs](from-keyspecs.md) | [jvm]<br>val [fromKeyspecs](from-keyspecs.md): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt; |
| [toHostname](to-hostname.md) | [jvm]<br>val [toHostname](to-hostname.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |
| [toHostspecs](to-hostspecs.md) | [jvm]<br>val [toHostspecs](to-hostspecs.md): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[AgentKeySpec](../-agent-key-spec/index.md)&gt; |
| [toUsername](to-username.md) | [jvm]<br>val [toUsername](to-username.md): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html) |