//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshSession](index.md)/[requestEnv](request-env.md)

# requestEnv

[jvm]\
abstract suspend fun [requestEnv](request-env.md)(name: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), value: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)

Request an environment variable for this session (RFC 4254 section 6.4). Call before requesting a shell, command, or subsystem. Servers may restrict names (OpenSSH uses AcceptEnv) and reject requests after process startup. Names and values are encoded as UTF-8. Returns false for NUL-containing input, a closed channel, or server rejection; rejection does not close the session.