//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[KnownHostsVerifier](index.md)

# KnownHostsVerifier

class [KnownHostsVerifier](index.md)(file: [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html), hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22) : [HostKeyVerifier](../-host-key-verifier/index.md)

A host key verifier that reads from an OpenSSH-style `known_hosts` file.

Currently supports:

- 
   Plain hostnames (no hashed hosts yet)
- 
   Wildcards (* and ?) in hostnames
- 
   Multiple keys per host

#### Parameters

jvm

| | |
|---|---|
| file | The `known_hosts` file to read. |

## Constructors

| | |
|---|---|
| [KnownHostsVerifier](-known-hosts-verifier.md) | [jvm]<br>constructor(file: [File](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/File.html), hostname: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), port: [Int](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-int/index.html) = 22) |

## Functions

| Name | Summary |
|---|---|
| [addKeys](../-host-key-verifier/add-keys.md) | [jvm]<br>open suspend fun [addKeys](../-host-key-verifier/add-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;) |
| [removeKeys](../-host-key-verifier/remove-keys.md) | [jvm]<br>open suspend fun [removeKeys](../-host-key-verifier/remove-keys.md)(keys: [List](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](../-public-key/index.md)&gt;) |
| [verify](verify.md) | [jvm]<br>open suspend override fun [verify](verify.md)(key: [PublicKey](../-public-key/index.md)): [Boolean](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-boolean/index.html)<br>Verify the server's host key. |