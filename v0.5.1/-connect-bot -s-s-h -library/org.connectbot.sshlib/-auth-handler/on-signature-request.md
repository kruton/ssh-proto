//[ConnectBot SSH Library](../../../index.md)/[org.connectbot.sshlib](../index.md)/[AuthHandler](index.md)/[onSignatureRequest](on-signature-request.md)

# onSignatureRequest

[jvm]\
abstract suspend fun [onSignatureRequest](on-signature-request.md)(key: [AuthPublicKey](../-auth-public-key/index.md), dataToSign: [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)): [ByteArray](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin/-byte-array/index.html)?

Called only for keys the server accepted (PK_OK). Return the signature over [dataToSign](on-signature-request.md), or null to skip this key.

The returned bytes are written verbatim into the publickey `SSH_MSG_USERAUTH_REQUEST` signature field — the library does not decode or repackage them. This makes the callback a clean extension point for externally-signed keys.

Use cases:

- 
   **Local private key**: call [SshSigning.sign](../-ssh-signing/sign.md).
- 
   **SSH agent**: forward [dataToSign](on-signature-request.md) to your agent and return its response.
- 
   **FIDO2 / Security Key** (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`): drive your CTAP2 stack with `clientDataHash = SHA-256(dataToSign)`, then return `org.connectbot.sshlib.sk.SkSignatureBlob.pack(algorithm, rawSignature, flags, counter)`. See `org.connectbot.sshlib.sk.SkAuthHelpers` for the matching public-key blob constructor.