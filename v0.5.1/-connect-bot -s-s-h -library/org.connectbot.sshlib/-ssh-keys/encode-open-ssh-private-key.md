//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshKeys](index.md)/[encodeOpenSshPrivateKey](encode-open-ssh-private-key.md)

# encodeOpenSshPrivateKey

[jvm]\
fun [encodeOpenSshPrivateKey](encode-open-ssh-private-key.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)

Encode a [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html) to OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`).

#### Return

OpenSSH-formatted private key string

#### Parameters

jvm

| | |
|---|---|
| keyPair | JCA key pair to encode |
| password | Optional passphrase to encrypt the key (AES-256-CTR with bcrypt KDF) |

#### Throws

| | |
|---|---|
| [SshException](../-ssh-exception/index.md) | if the key type is unsupported |