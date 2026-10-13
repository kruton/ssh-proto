//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshKeys](index.md)

# SshKeys

[jvm]\
object [SshKeys](index.md)

Key management utilities for SSH private keys.

Provides decoding/encoding of private keys in PEM, PKCS#8, and OpenSSH formats, and Ed25519 JCA provider registration for platforms that lack native support.

## Functions

| Name | Summary |
|---|---|
| [decodePemPrivateKey](decode-pem-private-key.md) | [jvm]<br>fun [decodePemPrivateKey](decode-pem-private-key.md)(pem: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html)<br>Decode a private key from PEM, PKCS#8, or OpenSSH format. |
| [encodeOpenSshPrivateKey](encode-open-ssh-private-key.md) | [jvm]<br>fun [encodeOpenSshPrivateKey](encode-open-ssh-private-key.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>Encode a [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html) to OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`). |
| [encodePemPrivateKey](encode-pem-private-key.md) | [jvm]<br>fun [encodePemPrivateKey](encode-pem-private-key.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)<br>Encode a [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html) to PEM format. |
| [ensureEd25519Support](ensure-ed25519-support.md) | [jvm]<br>fun [~~ensureEd25519Support~~](ensure-ed25519-support.md)()<br>Ed25519 support is now selected automatically without changing the global JCE provider list. |