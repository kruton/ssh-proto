//[ConnectBot SSH Library](index.md)

# ConnectBot SSH Library

[jvm]\
[[Continuous Integration](https://img.shields.io/github/actions/workflow/status/connectbot/cbssh/ci.yml?branch=main&label=CI)](https://github.com/connectbot/cbssh/actions/workflows/ci.yml?query=branch%3Amain)[[Maven Central](https://img.shields.io/maven-central/v/org.connectbot.sshlib/sshlib?label=Maven%20Central&color=blue)](https://central.sonatype.com/artifact/org.connectbot.sshlib/sshlib)[[License](https://img.shields.io/github/license/connectbot/cbssh?label=License&color=blue)](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/LICENSE)[[Quality Gate Status](https://img.shields.io/sonar/quality_gate/connectbot_cbssh?server=https%3A%2F%2Fsonarcloud.io&label=Quality%20Gate)](https://sonarcloud.io/summary/overall?id=connectbot_cbssh)[[Coverage](https://img.shields.io/sonar/coverage/connectbot_cbssh?server=https%3A%2F%2Fsonarcloud.io&label=Coverage)](https://sonarcloud.io/summary/overall?id=connectbot_cbssh)

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
   **Authentication**: `publickey` (including FIDO2/SK), `password`, `keyboard-interactive`
- 
   **Host Keys**: ML-DSA hybrid, Ed25519, Ed448, ECDSA, RSA (SHA-2)
- 
   **Key Exchange**: ML-KEM hybrid, SNTRUP761 hybrid, Curve25519, ECDH, DH groups 14/16/18,   DH group-exchange
- 
   **Encryption**: ChaCha20-Poly1305, AES-GCM, AES-CTR
- 
   **MACs**: HMAC-SHA2 (including ETM variants)

For a complete list of supported algorithms and their respective RFCs, see [docs/ALGORITHMS.md](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/docs/ALGORITHMS.md).

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

### FIDO2 / Security Key Authentication

The library supports authentication with `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` keys. Callers provide their own FIDO2 stack and surface the resulting assertion through the library's helpers.

See [docs/SK_AUTH.md](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/docs/SK_AUTH.md) for detailed implementation details and examples.

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
   [Changelog](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/CHANGELOG.md)
- 
   [Supported algorithms](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/docs/ALGORITHMS.md)
- 
   [Security Key authentication](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/docs/SK_AUTH.md)
- 
   [Integration testing](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/docs/agents/testing.md)

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

Changes since v0.5.1.

[Compare source versions](https://github.com/connectbot/cbssh/compare/v0.5.1...5eeee75c9799062a1babb1c036056edc72c9cd2b)

### SSH

No public API signature changes.

### Release notes

### Fixed

- Preserved unread session and forwarding output through automatic connection teardown after
  remote channel close, including exec stderr and buffered SFTP responses (#317).
- Released retained delivery workers and buffers on explicit session close or client disconnect,
  including when the network has already shut down.

[0.5.0]: https://github.com/connectbot/cbssh/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/connectbot/cbssh/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/connectbot/cbssh/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/connectbot/cbssh/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/connectbot/cbssh/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/connectbot/cbssh/compare/v0.2.1...v0.3.0

[View changelog](https://github.com/connectbot/cbssh/blob/5eeee75c9799062a1babb1c036056edc72c9cd2b/CHANGELOG.md)
<!-- END DOCS API CHANGES -->
