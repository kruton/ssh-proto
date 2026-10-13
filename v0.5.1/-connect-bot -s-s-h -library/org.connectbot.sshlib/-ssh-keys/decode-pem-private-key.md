//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshKeys](index.md)/[decodePemPrivateKey](decode-pem-private-key.md)

# decodePemPrivateKey

[jvm]\
fun [decodePemPrivateKey](decode-pem-private-key.md)(pem: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html)

Decode a private key from PEM, PKCS#8, or OpenSSH format.

Supports RSA, ECDSA (nistp256/384/521), and Ed25519 keys in:

- 
   OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`)
- 
   PEM/PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`)
- 
   PEM/SEC1 EC (`BEGIN EC PRIVATE KEY`)
- 
   PKCS#8 (`BEGIN PRIVATE KEY`)

#### Return

JCA [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html) containing both public and private keys

#### Parameters

jvm

| | |
|---|---|
| pem | Private key contents as a string |
| password | Passphrase for encrypted keys, or null if unencrypted |

#### Throws

| | |
|---|---|
| [SshException](../-ssh-exception/index.md) | if the key format is unrecognized or decryption fails |