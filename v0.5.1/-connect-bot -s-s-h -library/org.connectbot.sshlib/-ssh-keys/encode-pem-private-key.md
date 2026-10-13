//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[SshKeys](index.md)/[encodePemPrivateKey](encode-pem-private-key.md)

# encodePemPrivateKey

[jvm]\
fun [encodePemPrivateKey](encode-pem-private-key.md)(keyPair: [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html), password: [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)? = null): [String](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-string/index.html)

Encode a [KeyPair](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyPair.html) to PEM format.

- 
   RSA keys are encoded as PKCS#1 (`BEGIN RSA PRIVATE KEY`)
- 
   EC keys are encoded as SEC1 (`BEGIN EC PRIVATE KEY`)
- 
   Ed25519 keys are encoded as PKCS#8 (`BEGIN PRIVATE KEY`)

#### Return

PEM-encoded private key string

#### Parameters

jvm

| | |
|---|---|
| keyPair | JCA key pair to encode |
| password | Optional passphrase to encrypt the key. RSA and EC use legacy PEM AES-256-CBC encryption; Ed25519 uses PBES2 encrypted PKCS#8. |

#### Throws

| | |
|---|---|
| [SshException](../-ssh-exception/index.md) | if the key type is unsupported |