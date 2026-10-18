# Changelog

## Unreleased

Changes for library users since `0.6.1`.

## [0.6.1][0.6.1]

Changes for library users since `0.6.0`.

### Fixed

- Fixed connections to older SSH servers that terminate identification banners
  with LF instead of CRLF, including legacy OpenSSH servers.
- Tightened identification-banner validation to reject malformed banners and
  enforce the 255-byte limit including the line ending.

## [0.6.0][0.6.0]

Changes for library users since `0.5.1`.

### Added

- Added ML-KEM-768/P-256 and ML-KEM-1024/P-384 hybrid key exchanges,
  plus SNTRUP761/X25519 key exchange under both standard and OpenSSH names.
- Added opt-in pure ML-KEM key exchanges: `mlkem768-sha256` and
  `mlkem1024-sha384`.
- Added platform-backed ML-DSA-44/65/87 and ML-DSA-44/Ed25519 signatures
  for host verification, public-key authentication, and agent session binding,
  plus ML-DSA-87/P-384 composite host keys. Composite host algorithms are
  enabled by default when supported by an installed provider; pure ML-DSA
  host algorithms remain opt-in.
- Added private-key import and export for supported post-quantum keys,
  including encrypted OpenSSH and PKCS#8 PEM formats.
- Added OpenSSH host-key rotation support with proof verification, including
  post-quantum signatures.
- Exposed the connected peer address through `SshClient.remoteAddress` and
  the transport API.
- Added optional `AgentProvider` operations for adding and removing identities,
  confirmation and lifetime constraints, and agent locking and unlocking.

### Changed

- Published Maven artifacts now include SLSA provenance.

### Fixed

- Fixed multi-factor authentication to follow updated server authentication
  methods after partial success, retry keys for subsequent factors, and avoid
  reusing a key that already completed a factor.

## [0.5.1][0.5.1]

Changes for library users since `0.5.0`.

### Added

- Added `SshClientConfig.keepAliveIntervalMs` for SSH ignore-message heartbeats
  (thanks [@JDis03](https://github.com/JDis03)).
- Added session environment-variable requests.
- Added the SFTP `copy-data` extension for server-side file copies
  (thanks [@JDis03](https://github.com/JDis03)).

### Fixed

- Preserved unread session and forwarding output through automatic connection teardown after
  remote channel close, including exec stderr and buffered SFTP responses (#317).
- Released retained delivery workers and buffers on explicit session close or client disconnect,
  including when the network has already shut down.
- Contained background transport and chaff-write failures during shutdown and
  discarded in-flight channel data after local close
  (thanks [@ptgamr](https://github.com/ptgamr)).
- Enforced RFC 10042 hybrid key-exchange validation.

## [0.5.0][0.5.0]

Changes for library users since `0.4.2`.

### Added

- Added support for reading OpenSSH private keys encrypted with
  `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com`.
- Added `SshClientConfig.sessionWindowSize` and `SshClientConfig.sftpWindowSize`
  to configure receive windows for session channels and channels opened by
  `SshClient.openSftp` independently.

### Changed

- Increased default receive windows from 64 KiB to 2 MiB for session channels
  and 8 MiB for SFTP channels to improve throughput on higher-latency connections.
- Improved SSH and SFTP transfer performance by batching channel writes and
  receive-window updates, pipelining SFTP frames, and reducing buffer copies
  and allocations.
- Serialized protocol decisions independently of transport writes, keeping
  incoming packet processing and shutdown responsive under backpressure.

### Fixed

- Prevented valid packets arriving during suspended writes from causing
  spurious disconnects by serializing complete connection state transitions.
- Preserved reply ordering when requests are cancelled after being admitted
  for transmission.
- Released SFTP lifecycle locks before waiting for writes to prevent deadlocks
  under transport or channel-window backpressure.
- Cancelled pending remote forwarding handlers and released sockets and
  selector resources when forwarding ends or fails.
- Improved Android key compatibility by falling back to JVM Base64 operations
  when Android calls fail and accepting Ed25519 private keys with PKCS#8
  encodings regardless of their implementation class name.

## [0.4.2][0.4.2]

Changes for library users since `0.4.1`.

### Changed

- Deprecated `SshKeys.ensureEd25519Support()` because Ed25519 support is now
  selected automatically without modifying the global JCE provider list.

### Fixed

- Preserved unread session output, error output, extended data, and forwarded
  channel data when the remote peer closes a channel.
- Validated JCE providers with raw-key operations before selecting them for
  Ed25519, Ed448, ECDSA, RSA, and X25519, avoiding failures from providers such
  as AndroidKeyStore that advertise algorithms but reject non-keystore keys.

## [0.4.1][0.4.1]

Changes for library users since `0.4.0`.

### Changed

- Bound TLA+ Terrapin model to implementation and tightened up the SFTP model.

### Fixed

- Ensured channels are unregistered and old channels are closed in the registry.

## [0.4.0][0.4.0]

Changes for library users since `0.3.1`.

### Added

- Added `SshSession.exitInfo` (`Deferred<SessionExit>`) to expose remote execution
  exit status (`SessionExit.Status`) and exit signal (`SessionExit.Signal`) details
  sent via `SSH_MSG_CHANNEL_REQUEST` `exit-status` and `exit-signal` messages.
- Added formal TLA+ specifications and model checking for verifying state machine
  transitions, channel isolation, and Terrapin attack mitigation.

### Changed

- Converted channel lifecycle management to explicit state machines using `KStateMachine`
  to support formal modeling and strict state separation.
- Updated default algorithm preference lists to prioritize modern cryptographic
  ciphers, key exchanges, and MACs.

### Fixed

- Enforced strict session binding (session ID and host key verification) for forwarded
  SSH agent signing requests.
- Implemented receive-window backpressure across channel types (session, port
  forwarding, and agent) to prevent window overflows.
- Bounded nested field sizes and entry counts during SFTP response decoding to
  prevent excessive memory allocation from malformed responses.
- Verified host-key proof signatures prior to trusting host keys during key exchange.
- Validated parameter boundaries and key lengths during Diffie-Hellman group exchange.
- Directionally isolated rekeying state transitions to handle inbound and outbound
  key exchange independently.
- Decoupled SSH agent response handling from the main packet loop to prevent connection
  deadlocks.
- Hardened connection tear-down to ensure transport closure occurs cleanly and only
  once under concurrent close requests.
- Ensured `ssh-rsa` algorithm wishlist selections are honored when explicitly specified.
- Switched outbound SSH packet padding generation to cryptographically secure random values.
- Fixed passphrase encryption when exporting Ed25519 private keys to PKCS#8 format.

## [0.3.1][0.3.1]

Changes for library users since `0.3.0`.

### Fixed

- Restricted maximum length constraints on SSH agent messages and packet payload fields
  to prevent excessive memory allocation when processing untrusted wire data
  (GHSA-ch3q-cw5r-f4hg).
- Hardened DER length and integer parsing for ASN.1 private keys to prevent integer
  overflow and excessive memory allocation (GHSA-vc8p-8pxg-rfwg).

## [0.3.0][0.3.0]

Changes for library users since `0.2.1`.

### Added

- Added FIDO2 / Security Key authentication helpers for
  `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` keys
  in the new `org.connectbot.sshlib.sk` package. The library handles the SSH
  wire-format pieces while callers provide their own CTAP2 transport.
- Added `AuthHandler.onBanner(message)` so applications can display
  `SSH_MSG_USERAUTH_BANNER` messages during authentication.
- Added `KtorTcpTransport.getLocalAddress()` to expose the local socket address
  assigned to a connected TCP transport.
- Added `docs/ALGORITHMS.md` with the complete supported algorithm list and
  `docs/SK_AUTH.md` with Security Key authentication guidance.

### Changed

- `SshClient(...)` and `BlockingSshClient(...)` convenience constructors now
  require an explicit `HostKeyVerifier`. This makes host-key verification a
  required caller decision instead of allowing a convenience constructor that
  could not build a valid `SshClientConfig`.
- `AuthHandler.onSignatureRequest()` is documented as a verbatim signature
  extension point for local private keys, SSH agents, and FIDO2 authenticators.

### Fixed

- Authentication banners are now delivered to callers during every authentication
  step instead of only being logged.
- `SshSigning.sign()` now rejects `sk-*` algorithms with an actionable error,
  since Security Key private material lives on the authenticator and must be
  signed through `AuthHandler.onSignatureRequest()`.
- Hardened host-key signature verification by requiring the signature algorithm
  to match the negotiated host-key algorithm.
- Hardened agent session-binding signature verification by requiring the
  signature algorithm to be compatible with the key type.
- Hardened key exchange and channel handling by rejecting all-zero ECDH shared
  secrets, invalid DH group-exchange parameters, channel-window overflows, and
  incoming channel data that exceeds the local receive window.
- Limited zlib decompression output per packet to reduce decompression-bomb
  denial-of-service risk.

[0.6.1]: https://github.com/connectbot/cbssh/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/connectbot/cbssh/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/connectbot/cbssh/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/connectbot/cbssh/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/connectbot/cbssh/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/connectbot/cbssh/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/connectbot/cbssh/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/connectbot/cbssh/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/connectbot/cbssh/compare/v0.2.1...v0.3.0
