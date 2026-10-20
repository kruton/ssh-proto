//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthHandler](index.md)/[onKeyboardInteractivePrompt](on-keyboard-interactive-prompt.md)

# onKeyboardInteractivePrompt

[jvm]\
abstract suspend fun [onKeyboardInteractivePrompt](on-keyboard-interactive-prompt.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), instruction: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), prompts: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[KeyboardInteractiveCallback.Prompt](../-keyboard-interactive-callback/-prompt/index.md)&gt;): [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;?

Called when the server sends keyboard-interactive prompts. Return responses (one per prompt), or null to skip keyboard-interactive.