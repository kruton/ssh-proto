//[ConnectBot SSH Library](../../../../index.md)/[org.connectbot.sshlib](../../index.md)/[SshClientConfig](../index.md)/[Builder](index.md)/[environment](environment.md)

# environment

[jvm]\
var [environment](environment.md): [Map](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-map/index.html)&lt;[String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)&gt;

Environment variables sent before each session starts, including SFTP. Servers may ignore variables not allowed by their policy (OpenSSH AcceptEnv). Names and values use UTF-8 and must not contain NUL. Only supplied variables are sent.