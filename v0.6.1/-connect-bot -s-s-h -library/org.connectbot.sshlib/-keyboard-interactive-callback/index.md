//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[KeyboardInteractiveCallback](index.md)

# KeyboardInteractiveCallback

[jvm]\
interface [KeyboardInteractiveCallback](index.md)

Callback for keyboard-interactive authentication (RFC 4256).

The server sends one or more info requests, each containing prompts that the user must answer. [onInfoRequest](on-info-request.md) receives a `respond` callback; call it with the answers to send them back to the server.

## Types

| Name | Summary |
|---|---|
| [Prompt](-prompt/index.md) | [jvm]<br>data class [Prompt](-prompt/index.md)(val text: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), val echo: [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)) |

## Functions

| Name | Summary |
|---|---|
| [onInfoRequest](on-info-request.md) | [jvm]<br>abstract suspend fun [onInfoRequest](on-info-request.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), instruction: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), prompts: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[KeyboardInteractiveCallback.Prompt](-prompt/index.md)&gt;, respond: suspend (responses: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;) -&gt; [Unit](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-unit/index.html))<br>Called when the server sends an info request with prompts. |