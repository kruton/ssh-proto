//[ConnectBot SSH Library](index.md)

# ConnectBot SSH Library

[jvm]\
[[Continuous Integration](https://img.shields.io/github/actions/workflow/status/connectbot/cbssh/ci.yml?branch=main&label=CI)](https://github.com/connectbot/cbssh/actions/workflows/ci.yml?query=branch%3Amain)[[Maven Central](https://img.shields.io/maven-central/v/org.connectbot.sshlib/sshlib?label=Maven%20Central&color=blue)](https://central.sonatype.com/artifact/org.connectbot.sshlib/sshlib)[[SLSA v1 Build Level 3](https://img.shields.io/badge/SLSA%20v1-Build%20Level%203-blue)](https://slsa.dev/spec/v1.0/levels#build-l3-hardened-builds)[[License](https://img.shields.io/github/license/connectbot/cbssh?label=License&color=blue)](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/LICENSE)[[Quality Gate Status](https://img.shields.io/sonar/quality_gate/connectbot_cbssh?server=https%3A%2F%2Fsonarcloud.io&label=Quality%20Gate)](https://sonarcloud.io/summary/overall?id=connectbot_cbssh)[[Coverage](https://img.shields.io/sonar/coverage/connectbot_cbssh?server=https%3A%2F%2Fsonarcloud.io&label=Coverage)](https://sonarcloud.io/summary/overall?id=connectbot_cbssh)

ConnectBot SSH is a Kotlin client library for SSH connections, authentication, interactive shells, command execution, SFTP, and port forwarding. It uses coroutines, declarative protocol definitions, and explicit state machines.

The protocol parsing uses declarative Kaitai Struct specifications that auto-generate code from `.ksy` definitions. The internal state machine is defined in KStateMachine for clear separation of protocol states from the code that runs in reaction to state changes.

## Features

- 
   **SSH Client**: Coroutine API (`SshClient`) and blocking connection/authentication   wrapper (`BlockingSshClient`)
- 
   **Protocol Parsing**: SSH message parsing and serialization (RFCs 4250-4256,   4419, 5656, 8308, 8709, 8731, 9142)
- 
   **Channel I/O**: Interactive shells with PTY, command execution, subsystems,   stdout/stderr streams, exit status/signals, and flow control
- 
   **SFTP**: Version 3 file transfer with read/write/stat/directory operations   ([draft-ietf-secsh-filexfer](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer))
- 
   **Port Forwarding**: Local, remote, and dynamic (SOCKS5) port forwarding
- 
   **Agent Forwarding**: Forward SSH agent requests with session binding support
- 
   **Transport**: Pluggable transport layer (TCP via Ktor, or custom)
- 
   **Configuration**: Session environment variables, receive windows, automatic   rekeying, and optional zlib compression

## Algorithm Support

The library supports a wide range of post-quantum and other modern SSH algorithms, including:

- 
   **Authentication**: `publickey` (including OpenSSH certificates and FIDO2/SK), `password`, `keyboard-interactive`
- 
   **Host Keys**: ML-DSA hybrid, Ed25519, Ed448, ECDSA, RSA (SHA-2), OpenSSH host certificates
- 
   **Key Exchange**: ML-KEM hybrid, SNTRUP761 hybrid, Curve25519, ECDH, DH groups 14/16/18,   DH group-exchange
- 
   **Encryption**: ChaCha20-Poly1305, AES-GCM, AES-CTR
- 
   **MACs**: HMAC-SHA2 (including ETM variants)

For a complete list of supported algorithms and their respective RFCs, see [docs/ALGORITHMS.md](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/ALGORITHMS.md).

The defaults offer only encrypt-then-MAC (ETM) HMAC-SHA2 variants and exclude SHA-1 key exchange and MACs, CBC/3DES ciphers, and `ssh-rsa` host-key signatures. These legacy algorithms and non-ETM MACs remain available only through the explicit `kexAlgorithms`, `hostKeyAlgorithms`, `encryptionAlgorithms`, and `macAlgorithms` settings in `SshClientConfig`. RSA user authentication normally requires the server to advertise `rsa-sha2-256` or `rsa-sha2-512` through `server-sig-algs`. Explicitly including `ssh-rsa` in the configured host-key algorithm wishlist also permits the legacy RSA/SHA-1 signature when advertised, or as the base-key algorithm when that extension is absent.

## Quick Start

### Add the Library

The library targets JVM 17. Add the dependency from [Maven Central](https://central.sonatype.com/artifact/org.connectbot.sshlib/sshlib):

```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("org.connectbot.sshlib:sshlib:0.5.0")
}
```

### Build

Published artifacts from the attested build pipeline include SLSA provenance and SBOM attestations. See [verifying build provenance](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/BUILD_PROVENANCE.md) for Maven/Gradle downloads, standard verification commands, and downstream build use.

Building from source requires JDK 17 and a running Docker daemon for integration tests. The Gradle wrapper handles Gradle installation.

```bash
./gradlew build

# Compile the library without running tests:
./gradlew :sshlib:compileKotlin
```

### Use the Test CLI Client

There is a &quot;testapp&quot; that allows you to try the library from a test client app. You can use it by running the following commands:

```bash
./gradlew :testapp:installDist
./testapp/build/install/testapp/bin/testapp user@host
./testapp/build/install/testapp/bin/testapp -p 2222 user@host

# Authenticate with a private key:
./testapp/build/install/testapp/bin/testapp -i ~/.ssh/id_ed25519 user@host

# Enable more debug logging:
./testapp/build/install/testapp/bin/testapp -d user@host
```

### Library API

Connection, authentication, and channel I/O use suspend functions. Every client requires an explicit `HostKeyVerifier`. This example trusts keys already present in an OpenSSH `known_hosts` file; `KnownHostsVerifier` supports plain hostnames and wildcards, but does not support hashed hostnames.

```kotlin
import java.io.File
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import org.connectbot.sshlib.*

suspend fun main() {
    val verifier = KnownHostsVerifier(
        File(System.getProperty("user.home"), ".ssh/known_hosts"),
        "example.com"
    )
    val client = SshClient("example.com", port = 22, hostKeyVerifier = verifier)
    try {
        check(client.connect() is ConnectResult.Success) { "SSH connection failed" }
        check(client.authenticatePassword("user", "pass") is AuthResult.Success) {
            "SSH authentication failed"
        }

        val session = checkNotNull(client.openSession()) { "Failed to open SSH session" }
        try {
            check(session.requestPty()) { "Server rejected PTY request" }
            check(session.requestShell()) { "Server rejected shell request" }

            coroutineScope {
                launch {
                    for (chunk in session.stderr) System.err.write(chunk)
                }
                session.write("ls\nexit\n".toByteArray())
                for (chunk in session.stdout) System.out.write(chunk)
            }
        } finally {
            session.close()
        }
    } finally {
        client.disconnect()
    }
}
```

`stdout` and `stderr` are `ReceiveChannel<ByteArray>` streams. Alternatively, `session.read()` reads stdout and returns `null` at EOF. Read both streams concurrently when the remote process may produce both. Output remains readable after remote channel close and automatic disconnect; explicit `session.close()` or `client.disconnect()` discards unread output.

For synchronous connection and authentication calls, use `org.connectbot.sshlib.blocking.BlockingSshClient`. Its session and SFTP objects still expose suspend functions for I/O.

By default, the client disconnects when its last channel closes. Set `autoDisconnectOnLastChannelClose = false` to keep an authenticated connection available for later sessions or transfers, then disconnect it explicitly.

### Configuration

```kotlin
val client = SshClient(SshClientConfig {
    host = "example.com"
    hostKeyVerifier = myVerifier
    autoDisconnectOnLastChannelClose = false
    enableCompression = true // Offers zlib@openssh.com, zlib, and none
    environment = mapOf("LANG" to "en_US.UTF-8")
    sessionWindowSize = 2 * 1024 * 1024 // Default: 2 MiB per session
    sftpWindowSize = 8 * 1024 * 1024    // Default: 8 MiB per SFTP channel
})
```

Environment defaults are sent before starting each session, including SFTP. Servers may reject variables according to their policy (OpenSSH `AcceptEnv`). For individual sessions, call `session.requestEnv(name, value)` before requesting a shell, command, or subsystem. Each channel can buffer up to its configured receive window in unread data.

### Command Execution

With an already connected and authenticated `client`, open a fresh session for each command. Only one shell, command, or subsystem can start on a session.

```kotlin
val session = checkNotNull(client.openSession())
try {
    check(session.requestExec("uname -a")) { "Server rejected command" }
    coroutineScope {
        launch {
            for (chunk in session.stderr) System.err.write(chunk)
        }
        for (chunk in session.stdout) System.out.write(chunk)
    }
    when (val exit = session.exitInfo.await()) {
        is SessionExit.Status -> println("Exit code: ${exit.code}")
        is SessionExit.Signal -> println("Terminated by signal: ${exit.signalName}")
        null -> println("Server did not report an exit status or signal")
    }
} finally {
    session.close()
}
```

### SFTP File Transfer

With an already connected and authenticated `client`:

```kotlin
val sftp = when (val result = client.openSftp()) {
    is SftpResult.Success -> result.value
    else -> error("Failed to open SFTP: $result")
}

try {
    // List a directory
    when (val result = sftp.listdir("/home/user")) {
        is SftpResult.Success -> result.value.forEach { println(it.filename) }
        is SftpResult.ServerError -> println("Server error: ${result.message}")
        else -> println("Error: $result")
    }

    // Read a file
    val handle = sftp.open("/home/user/file.txt", setOf(SftpOpenFlag.READ)).getOrThrow()
    try {
        val data = sftp.read(handle, 0L, 4096).getOrThrow() // ByteArray? (null on EOF)
    } finally {
        sftp.close(handle).getOrThrow()
    }
} finally {
    sftp.close()
}
```

### OpenSSH Certificate Authentication

The library supports OpenSSH user and host certificates, CA trust, and KRL revocation checks.

See [docs/SSH_CERTIFICATES.md](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/SSH_CERTIFICATES.md) for configuration and authentication examples.

### FIDO2 / Security Key Authentication

The library supports authentication with `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` keys. Callers provide their own FIDO2 stack and surface the resulting assertion through the library's helpers.

See [docs/SK_AUTH.md](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/SK_AUTH.md) for detailed implementation details and examples.

### SSH Agent Forwarding

Enable SSH agent forwarding to allow remote servers to use your keys:

```kotlin
// Implement an agent provider
class MyAgentProvider : AgentProvider {
    override suspend fun getIdentities(): AgentResult<List<AgentIdentity>> {
        val keyBlob = loadPublicKeyBlob()
        return AgentResult.Success(listOf(AgentIdentity(keyBlob, "my-key")))
    }

    override suspend fun signData(context: AgentSigningContext): AgentResult<ByteArray?> {
        // Show approval UI to user with session context
        val approved = showSigningPrompt(
            "Remote server ${context.serverHostKey.joinToString("") { "%02x".format(it) }} wants to use your key",
            "Session bound: ${context.isBound}"
        )

        return AgentResult.Success(if (approved) {
            // Return an SSH-encoded signature blob, honoring RSA SHA-2 flags.
            signWithPrivateKey(context.publicKeyBlob, context.dataToSign, context.flags)
        } else {
            null  // Deny the request
        })
    }
}

// Enable agent forwarding
val client = SshClient("bastion.example.com", hostKeyVerifier = myVerifier)
check(client.connect() is ConnectResult.Success) { "SSH connection failed" }
check(client.authenticatePassword("user", "pass") is AuthResult.Success) {
    "SSH authentication failed"
}
client.enableAgentForwarding(MyAgentProvider())

// Now remote servers can use your agent through forwarding
val session = checkNotNull(client.openSession()) { "Failed to open SSH session" }
check(session.requestShell()) { "Server rejected shell request" }
// When you SSH from bastion to another server, it can request signatures
```

## Compatibility Testing

The library is tested against multiple SSH server implementations using Docker (via Testcontainers):

- 
   **OpenSSH** 9.9p2 — full integration tests including port forwarding
- 
   **AsyncSSH** (Python) — compatibility tests for ciphers, key exchange, MACs,   and public key auth
- 
   **Dropbear** — compatibility tests including ML-KEM post-quantum key exchange

Run integration tests with: `./gradlew :sshlib:test` (requires Docker).

## Current Limitations

- 
   Client-only (no server implementation)
- 
   JVM library (targets Java 17 bytecode; not Kotlin Multiplatform)
- 
   `KnownHostsVerifier` does not support hashed hostnames

## Documentation

- 
   [Changelog](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/CHANGELOG.md)
- 
   [Supported algorithms](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/ALGORITHMS.md)
- 
   [Security Key authentication](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/SK_AUTH.md)
- 
   [Integration testing](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/docs/agents/testing.md)

## License

Apache License 2.0 - See LICENSE file

## Copyright

Copyright 2019-2026, [Kenny Root](https://github.com/kruton/)

## Packages

| Name |
|---|
| [org.connectbot.sshlib](-connect-bot -s-s-h -library/org.connectbot.sshlib/index.md) |
| [org.connectbot.sshlib.blocking](-connect-bot -s-s-h -library/org.connectbot.sshlib.blocking/index.md) |
| [org.connectbot.sshlib.client](-connect-bot -s-s-h -library/org.connectbot.sshlib.client/index.md) |
| [org.connectbot.sshlib.sk](-connect-bot -s-s-h -library/org.connectbot.sshlib.sk/index.md) |
| [org.connectbot.sshlib.transport](-connect-bot -s-s-h -library/org.connectbot.sshlib.transport/index.md) |

<!-- BEGIN DOCS API CHANGES -->
## New and changed APIs

Changes since v0.6.1.

[Compare source versions](https://github.com/connectbot/cbssh/compare/v0.6.1...v0.6.2)

### SSH

#### org.connectbot.sshlib.AlgorithmCategory

- Added: [CIPHER](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-category/-c-i-p-h-e-r/index.html)

- Added: [HOST_KEY](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-category/-h-o-s-t_-k-e-y/index.html)

- Added: [KEX](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-category/-k-e-x/index.html)

- Added: [MAC](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-category/-m-a-c/index.html)

- Added: [PUBKEY](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-category/-p-u-b-k-e-y/index.html)

- Added: [enum AlgorithmCategory : Enum<AlgorithmCategory> ](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-category/index.html)

#### org.connectbot.sshlib.AlgorithmPolicyWarning

- Added: [constructor(category: AlgorithmCategory, algorithm: String, reason: AlgorithmPolicyWarningReason)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning/-algorithm-policy-warning.html)

- Added: [val algorithm: String](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning/algorithm.html)

- Added: [val category: AlgorithmCategory](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning/category.html)

- Added: [val reason: AlgorithmPolicyWarningReason](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning/reason.html)

- Added: [data class AlgorithmPolicyWarning(val category: AlgorithmCategory, val algorithm: String, val reason: AlgorithmPolicyWarningReason)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning/index.html)

#### org.connectbot.sshlib.AlgorithmPolicyWarningReason

- Added: [DH_TOO_SMALL](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning-reason/-d-h_-t-o-o_-s-m-a-l-l/index.html)

- Added: [RSA_TOO_SMALL](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning-reason/-r-s-a_-t-o-o_-s-m-a-l-l/index.html)

- Added: [UNAVAILABLE](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning-reason/-u-n-a-v-a-i-l-a-b-l-e/index.html)

- Added: [UNSUPPORTED](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning-reason/-u-n-s-u-p-p-o-r-t-e-d/index.html)

- Added: [enum AlgorithmPolicyWarningReason : Enum<AlgorithmPolicyWarningReason> ](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-algorithm-policy-warning-reason/index.html)

#### org.connectbot.sshlib.CertificateAuthorityVerifier

- Added: [constructor(hostname: String, trustedAuthorities: List<PublicKey>, revocations: SshKeyRevocationList? = null)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-certificate-authority-verifier/-certificate-authority-verifier.html)

- Added: [open suspend override fun verify(key: PublicKey): Boolean](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-certificate-authority-verifier/verify.html)

- Added: [class CertificateAuthorityVerifier constructor(hostname: String, trustedAuthorities: List<PublicKey>, revocations: SshKeyRevocationList? = null) : HostKeyVerifier](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-certificate-authority-verifier/index.html)

#### org.connectbot.sshlib.CryptoPolicyPreset

- Added: [DEFAULT](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-crypto-policy-preset/-d-e-f-a-u-l-t/index.html)

- Added: [FIPS](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-crypto-policy-preset/-f-i-p-s/index.html)

- Added: [FUTURE](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-crypto-policy-preset/-f-u-t-u-r-e/index.html)

- Added: [LEGACY](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-crypto-policy-preset/-l-e-g-a-c-y/index.html)

- Added: [enum CryptoPolicyPreset : Enum<CryptoPolicyPreset> ](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-crypto-policy-preset/index.html)

#### org.connectbot.sshlib.KnownHostsVerifier

- Changed: [constructor(file: File, hostname: String, port: Int = 22)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-known-hosts-verifier/-known-hosts-verifier.html)

- Changed: [constructor(file: File, hostname: String, port: Int, revocations: SshKeyRevocationList)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-known-hosts-verifier/-known-hosts-verifier.html)

- Changed: [constructor(file: File, hostname: String, revocations: SshKeyRevocationList)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-known-hosts-verifier/-known-hosts-verifier.html)

#### org.connectbot.sshlib.SshAlgorithm

- Added: [constructor(name: String, available: Boolean, defaultEnabled: Boolean)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-algorithm/-ssh-algorithm.html)

- Added: [val available: Boolean](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-algorithm/available.html)

- Added: [val defaultEnabled: Boolean](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-algorithm/default-enabled.html)

- Added: [val name: String](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-algorithm/name.html)

- Added: [data class SshAlgorithm(val name: String, val available: Boolean, val defaultEnabled: Boolean)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-algorithm/index.html)

#### org.connectbot.sshlib.SshCertificate

- Added: [fun toAuthPublicKey(): AuthPublicKey](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/to-auth-public-key.html)

- Added: [object Companion](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-companion/index.html)

- Added: [val algorithmName: String](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/algorithm-name.html)

- Added: [val criticalOptions: Map<String, ByteArray>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/critical-options.html)

- Added: [val encoded: ByteArray](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/encoded.html)

- Added: [val extensions: Map<String, ByteArray>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/extensions.html)

- Added: [val keyId: String](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/key-id.html)

- Added: [val principals: List<String>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/principals.html)

- Added: [val publicKey: PublicKey](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/public-key.html)

- Added: [val serial: ULong](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/serial.html)

- Added: [val signatureKey: PublicKey](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/signature-key.html)

- Added: [val type: SshCertificate.Type](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/type.html)

- Added: [val validAfter: ULong](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/valid-after.html)

- Added: [val validBefore: ULong](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/valid-before.html)

- Added: [class SshCertificate](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/index.html)

#### org.connectbot.sshlib.SshCertificate.Companion

- Added: [fun decode(encoded: ByteArray): SshCertificate](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-companion/decode.html)

- Added: [fun decode(text: String): SshCertificate](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-companion/decode.html)

- Added: [object Companion](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-companion/index.html)

#### org.connectbot.sshlib.SshCertificate.Type

- Added: [HOST](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-type/-h-o-s-t/index.html)

- Added: [USER](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-type/-u-s-e-r/index.html)

- Added: [enum Type : Enum<SshCertificate.Type> ](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-certificate/-type/index.html)

#### org.connectbot.sshlib.SshClient

- Changed: [suspend fun authenticatePublicKey(username: String, privateKeyData: ByteArray, certificate: SshCertificate, passphrase: String? = null): AuthResult](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client/authenticate-public-key.html)

- Changed: [suspend fun authenticatePublicKey(username: String, privateKeyData: ByteArray, passphrase: String? = null): AuthResult](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client/authenticate-public-key.html)

- Changed: [suspend fun authenticatePublicKey(username: String, privateKeyData: String, certificate: SshCertificate, passphrase: String? = null): AuthResult](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client/authenticate-public-key.html)

- Changed: [suspend fun authenticatePublicKey(username: String, privateKeyData: String, passphrase: String? = null): AuthResult](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client/authenticate-public-key.html)

- Added: [val policyWarnings: List<AlgorithmPolicyWarning>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client/policy-warnings.html)

#### org.connectbot.sshlib.SshClientConfig

- Added: [val algorithmWarningHandler: (AlgorithmPolicyWarning) -> Unit?](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/algorithm-warning-handler.html)

- Added: [val cryptoPolicy: SshCryptoPolicy?](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/crypto-policy.html)

- Added: [val pubkeyAlgorithms: String?](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/pubkey-algorithms.html)

#### org.connectbot.sshlib.SshClientConfig.Builder

- Added: [fun cryptoPolicy(value: SshCryptoPolicy): SshClientConfig.Builder](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/-builder/crypto-policy.html)

- Added: [fun enableCertificateHostKeys(enabled: Boolean = true): SshClientConfig.Builder](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/-builder/enable-certificate-host-keys.html)

- Added: [var algorithmWarningHandler: (AlgorithmPolicyWarning) -> Unit?](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/-builder/algorithm-warning-handler.html)

- Added: [var pubkeyAlgorithms: String?](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-client-config/-builder/pubkey-algorithms.html)

#### org.connectbot.sshlib.SshCryptoPolicy

- Added: [object Companion](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/-companion/index.html)

- Added: [val algorithms: Map<AlgorithmCategory, List<String>>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/algorithms.html)

- Added: [val minimumDhBits: Int](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/minimum-dh-bits.html)

- Added: [val minimumRsaBits: Int](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/minimum-rsa-bits.html)

- Added: [val preset: CryptoPolicyPreset](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/preset.html)

- Added: [val warnings: List<AlgorithmPolicyWarning>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/warnings.html)

- Added: [class SshCryptoPolicy](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/index.html)

#### org.connectbot.sshlib.SshCryptoPolicy.Companion

- Added: [fun catalog(): Map<AlgorithmCategory, List<SshAlgorithm>>](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/-companion/catalog.html)

- Added: [fun resolve(preset: CryptoPolicyPreset = CryptoPolicyPreset.DEFAULT, overrides: Map<AlgorithmCategory, String> = emptyMap(), minimumRsaBits: Int? = null, minimumDhBits: Int? = null): SshCryptoPolicy](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/-companion/resolve.html)

- Added: [fun validateExpression(expression: String?)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/-companion/validate-expression.html)

- Added: [object Companion](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-crypto-policy/-companion/index.html)

#### org.connectbot.sshlib.SshKeyRevocationList

- Added: [fun isRevoked(key: PublicKey): Boolean](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-key-revocation-list/is-revoked.html)

- Added: [object Companion](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-key-revocation-list/-companion/index.html)

- Added: [class SshKeyRevocationList](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-key-revocation-list/index.html)

#### org.connectbot.sshlib.SshKeyRevocationList.Companion

- Added: [fun decode(encoded: ByteArray): SshKeyRevocationList](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-key-revocation-list/-companion/decode.html)

- Added: [object Companion](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib/-ssh-key-revocation-list/-companion/index.html)

#### org.connectbot.sshlib.blocking.BlockingSshClient

- Changed: [fun authenticatePublicKey(username: String, privateKeyData: ByteArray, certificate: SshCertificate, passphrase: String? = null)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib.blocking/-blocking-ssh-client/authenticate-public-key.html)

- Changed: [fun authenticatePublicKey(username: String, privateKeyData: ByteArray, passphrase: String? = null)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib.blocking/-blocking-ssh-client/authenticate-public-key.html)

- Changed: [fun authenticatePublicKey(username: String, privateKeyData: String, certificate: SshCertificate, passphrase: String? = null)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib.blocking/-blocking-ssh-client/authenticate-public-key.html)

- Changed: [fun authenticatePublicKey(username: String, privateKeyData: String, passphrase: String? = null)](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib.blocking/-blocking-ssh-client/authenticate-public-key.html)

#### org.connectbot.sshlib.client.SshConnection

- Changed: [constructor(transport: Transport, clientVersion: String = "SSH-2.0-CBSSH_1.0", hostKeyVerifier: HostKeyVerifier, kexAlgorithms: String = KexEntry.defaultString, hostKeyAlgorithms: String = SignatureEntry.defaultString, encryptionAlgorithms: String = CipherEntry.defaultString, macAlgorithms: String = MacEntry.defaultString, compressionAlgorithms: String = CompressionEntry.defaultString, preferPasswordAuth: Boolean = false, rekeyIntervalMs: Long, rekeyBytesLimit: Long, obscureKeystrokeTimingIntervalMs: Long = 20, coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO, pubkeyAlgorithms: String? = null, cryptoPolicy: SshCryptoPolicy? = null, onAlgorithmWarning: (AlgorithmPolicyWarning) -> Unit = {})](-connect-bot%20-s-s-h%20-library/org.connectbot.sshlib.client/-ssh-connection/-ssh-connection.html)

### Release notes

Changes for library users since `0.6.1`.

### Added

- Added OpenSSH user and host certificate support for Ed25519, RSA, and ECDSA,
  including certificate authentication overloads for async and blocking clients.
  Security Key user certificates are supported through application-provided signers.
- Added opt-in host certificate negotiation, CA trust through `KnownHostsVerifier`
  and `CertificateAuthorityVerifier`, and OpenSSH key revocation list support
  through `SshKeyRevocationList`. See [SSH certificates](docs/SSH_CERTIFICATES.md).
- Added `SshCryptoPolicy` with `DEFAULT`, `FUTURE`, `FIPS`, and `LEGACY` presets,
  custom algorithm expressions, and minimum RSA and Diffie-Hellman key sizes.
  The `FIPS` preset filters algorithms; it does not establish FIPS validation.
- Added an algorithm catalog with provider availability, independent public-key
  authentication algorithm selection, and structured policy warnings.

### Fixed

- Fixed a Poly1305 final-carry error that could cause intermittent
  `chacha20-poly1305@openssh.com` interoperability failures by using the
  Bouncy Castle implementation
  (thanks [@THEBMOREJOKER](https://github.com/THEBMOREJOKER)).

[0.6.2]: https://github.com/connectbot/cbssh/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/connectbot/cbssh/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/connectbot/cbssh/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/connectbot/cbssh/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/connectbot/cbssh/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/connectbot/cbssh/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/connectbot/cbssh/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/connectbot/cbssh/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/connectbot/cbssh/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/connectbot/cbssh/compare/v0.2.1...v0.3.0

[View changelog](https://github.com/connectbot/cbssh/blob/1a1c6547814ae75f96469598e374bfc5c32f11e1/CHANGELOG.md)
<!-- END DOCS API CHANGES -->
