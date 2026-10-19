//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthHandler](index.md)/[onBanner](on-banner.md)

# onBanner

[jvm]\
open suspend fun [onBanner](on-banner.md)(message: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html))

Called when the server sends an authentication banner (SSH_MSG_USERAUTH_BANNER). This is often used for out-of-band authentication instructions (e.g., a URL to visit).