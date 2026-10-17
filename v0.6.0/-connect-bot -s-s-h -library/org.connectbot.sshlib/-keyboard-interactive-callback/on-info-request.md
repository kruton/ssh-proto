//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[KeyboardInteractiveCallback](index.md)/[onInfoRequest](on-info-request.md)

# onInfoRequest

[jvm]\
abstract suspend fun [onInfoRequest](on-info-request.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), instruction: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), prompts: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[KeyboardInteractiveCallback.Prompt](-prompt/index.md)&gt;, respond: suspend (responses: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;) -&gt; [Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html))

Called when the server sends an info request with prompts.

#### Parameters

jvm

| | |
|---|---|
| name | Name of the authentication request (may be empty) |
| instruction | Instructions for the user (may be empty) |
| prompts | List of prompts the user must answer |
| respond | Call this with the list of responses (one per prompt) |