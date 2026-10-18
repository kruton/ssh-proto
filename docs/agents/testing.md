# Integration Testing Reference

This file covers integration test servers, how to add new ones, known compatibility quirks,
and the test key inventory for agents working on tests.

## SonarCloud Coverage

CI imports both JVM Kover coverage and Python coverage for the SNTRUP vendoring script.
Reproduce the reports locally before running `./gradlew sonar`:

```sh
./gradlew build koverXmlReport -PjdkVersion=25
python3 -m venv build/python-coverage
build/python-coverage/bin/pip install -r .github/scripts/requirements-coverage.txt
build/python-coverage/bin/python -m coverage run -m unittest discover -s .github/scripts -p 'test_vendor_sntrup.py' -v
build/python-coverage/bin/python -m coverage xml
```

Java 25 matches the CI analysis job and exercises native ML-KEM support; Java 17 skips
those runtime-dependent tests. The Python XML report is written to
`build/reports/python/coverage.xml`; `.coveragerc` keeps source paths relative for CI.

### Pull request quality gate

The repository ruleset requires `SonarCloud Code Analysis` from the SonarQube Cloud
GitHub App for `main` and release branches. The `SonarCloud` workflow runs after CI
and waits up to five minutes for the gate. Gate failures and timeouts fail analysis.

Java 25 PR builds test the exact PR head and upload bytecode, dependency JARs,
Kover XML, and Python coverage using `stageSonarInputs`. The Java 17 and 21 jobs
retain merge-commit testing. Builds receive no `SONAR_TOKEN`, including builds of
in-repository PRs. Fork PRs use the same automated process once GitHub permits their
CI run; no maintainer-created branch is needed.

A reusable workflow in `connectbot/actions` validates the producer run and current
PR head, fetches source independently, and scans on a fresh runner. Only the
standalone scanner receives `SONAR_TOKEN`; it never executes the PR's build scripts.
Analysis settings come from `.github/sonar.json` on the default-branch revision
running the consumer, not from the PR. Settings changes take effect after merging.
The existing Gradle `sonar` task remains available for local trusted analysis.

Missing/invalid artifacts fail validation. Closed PRs, superseded attempts, and
outdated heads skip without creating a passing Sonar check. Re-run all CI jobs to regenerate
expired artifacts or retry an interrupted scan. The consumer workflow must exist
on the default branch before `workflow_run` can trigger it. Keep the App's check
required: the consumer workflow's own GitHub check is on the default-branch context.

Default/release branch pushes and scheduled default-branch builds also use this
isolated scan to refresh comparison baselines. Coverage reports are build outputs,
not independent proof of the tests a contributor ran.

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
| `LegacyOpenSshCompatibilityTest` | OpenSSH 3.7.1p2, 5.0p1, 5.3p1, 7.4p1 | `legacy-openssh-server/` | 22 | `Server listening` |

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
  against `MlKemTestServer`, which uses independent BC ML-KEM and direct JCA
  ECDH. BC remains test-only. The P-256 variant also runs against real OpenSSH.
- **Dropbear + custom options**: The `DropbearCompatibilityTest.authenticateWithOptions()` helper spins up a fresh container with custom `OPTIONS` env var (passed to `dropbear` CLI). Used for host key type tests with `-r <keypath>`.

- **Pure ML-KEM**: Both opt-in variants are tested with independent BC
  encapsulation, including authentication, encrypted channels after rekey,
  malformed ciphertexts, fixed-width secret encoding, and cleanup.
- **ML-DSA-87/P-384**: Conscrypt provides the production-style composite service
  in tests. Its signatures are checked independently with BC ML-DSA-87 and JCA
  SHA384withECDSA over the draft's message representative. Schemas cover the
  nested SSH EC point and scalar encodings; PEM round trips cover both keys.

## Test Keys

Test key pairs are in `sshlib/src/test/resources/keys/`. Available types: ed25519,
ecdsa256/384/521, rsa (both encrypted and unencrypted variants, plus PEM and PKCS#8 formats).
The OpenSSH integration test also has its own `test_ed25519` key pair in the
`openssh-server/` resource dir.
