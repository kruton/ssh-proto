//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[KnownHostsVerifier](index.md)/[KnownHostsVerifier](-known-hosts-verifier.md)

# KnownHostsVerifier

[jvm]\
constructor(file: [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html), hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22)

#### Parameters

jvm

| | |
|---|---|
| file | The `known_hosts` file to read. |

[jvm]\
constructor(file: [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html), hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html), revocations: [SshKeyRevocationList](../-ssh-key-revocation-list/index.md))

Use an application-loaded KRL snapshot in addition to known_hosts revocations.

[jvm]\
constructor(file: [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html), hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), revocations: [SshKeyRevocationList](../-ssh-key-revocation-list/index.md))