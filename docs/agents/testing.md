# Integration Testing Reference

This file covers integration test servers, how to add new ones, known compatibility quirks,
and the test key inventory for agents working on tests.

## Test Servers

Integration tests live in `sshlib/src/test/.../client/` and use **Testcontainers** to spin up
real SSH servers in Docker. All require Docker to be running.

| Test class | Server | Docker resource dir | Port | Wait log pattern |
|---|---|---|---|---|
| `SshClientIntegrationTest` | OpenSSH 10.6p1 | `openssh-server/` | 22 | `Server listening` |
| `PortForwardingIntegrationTest` | OpenSSH 10.6p1 | `openssh-server/` | 22 | `Server listening` |
| `SftpClientIntegrationTest` | OpenSSH 10.6p1 | `openssh-server/` | 22 | `Server listening` |
| `AsyncSshCompatibilityTest` | AsyncSSH (Python) | `asyncssh-server/` | 8022 | `LISTENER READY` |
| `DropbearCompatibilityTest` | Dropbear | `dropbear-server/` | 22 | `Not backgrounding` |

All servers use credentials `testuser` / `testpass`. Public keys from `resources/keys/*.pub`
are injected into the Docker build via `withFileFromClasspath`.

## Adding a New Server or Test

1. Create a Docker resource directory under `sshlib/src/test/resources/` with a `Dockerfile`.
2. In the test class, build the image with `ImageFromDockerfile("name", false).withFileFromClasspath(".", "dir-name")`.
3. Inject test public keys with `.withFileFromClasspath("keyname.pub", "keys/keyname.pub")`.
4. Use `BlockingSshClient` for tests (wraps `SshClient` with `runBlocking`).
5. Parameterize algorithm tests with `@ParameterizedTest` + `@MethodSource`.

## Known Compatibility Issues

- **ML-DSA**: Conscrypt and Bouncy Castle are JVM test-only dependencies. Composite tests
  temporarily register Conscrypt and remove it in `finally`; annotate such tests with
  `@ResourceLock("JCA_PROVIDERS")`. Bouncy Castle independently checks component signatures.

- **Dropbear + RSA pubkey auth**: Dropbear rejects RSA public key authentication. The `rsa_unencrypted` key is excluded from Dropbear pubkey tests.
- **AsyncSSH + legacy algorithms**: AsyncSSH disables legacy algorithms by default. The server's `create_server()` call in `server.py` explicitly enables them (CBC ciphers, DH group1, hmac-sha1, etc.).
- **AsyncSSH + ML-KEM**: AsyncSSH requires the `liboqs` C library for post-quantum kex (`mlkem768x25519-sha256`). This is not installed in the test Docker image, so that server does not exercise ML-KEM; Dropbear covers the X25519 hybrid.

- **ML-KEM/NIST hybrids**: OpenSSH 10.6 supports `mlkem768nistp256-sha256` but not
  `mlkem1024nistp384-sha384`. Both are tested through authentication and rekey
  against `NistHybridTestServer`, which uses independent BC ML-KEM and direct JCA
  ECDH. BC remains test-only. The P-256 variant also runs against real OpenSSH.
- **Dropbear + custom options**: The `DropbearCompatibilityTest.authenticateWithOptions()` helper spins up a fresh container with custom `OPTIONS` env var (passed to `dropbear` CLI). Used for host key type tests with `-r <keypath>`.

## Test Keys

Test key pairs are in `sshlib/src/test/resources/keys/`. Available types: ed25519,
ecdsa256/384/521, rsa (both encrypted and unencrypted variants, plus PEM and PKCS#8 formats).
The OpenSSH integration test also has its own `test_ed25519` key pair in the
`openssh-server/` resource dir.
