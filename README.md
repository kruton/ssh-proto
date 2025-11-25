# SSH Protocol Parsing with Kaitai Struct

A comprehensive SSH protocol parser implemented using declarative Kaitai
Struct specifications. This project auto-generates protocol parsing and
serialization code for the SSH wire protocol.

## Project Status: Protocol Parsing

This implementation provides SSH wire protocol parsing for all major RFCs
and modern algorithms:

- **Core RFCs**: 4250-4256, 4419, 5656, 8308, 8709, 8731, 9142
- **Key Exchange**: DH, ECDH (all others use these same messages)
- **Ciphers**: AES (CBC/CTR/GCM), ChaCha20-Poly1305, 3DES
- **Signatures**: RSA, DSS, ECDSA, Ed25519, Ed448 (with component parsing)
- **Authentication**: publickey, password, keyboard-interactive, hostbased,
  GSSAPI
- **OpenSSH Extensions**: Unix socket forwarding, host key rotation, VPN
  tunneling
- **Channel Types**: session, exec, shell, port forwarding, X11, SFTP,
  subsystems


## What This Project Provides

### Protocol Parser
- Parse SSH messages from binary streams
- Serialize SSH messages to binary format
- Extract all message fields and components
- Support for all modern and legacy algorithms

### Message Structures
- SSH message types defined
- Signature and public key component extraction
- Algorithm-specific payload parsing
- Comprehensive enums for all protocol constants

### State Machine (In progress)
- Basic connection state machine framework (SMC)
- States defined but transitions incomplete
- Intended for connection lifecycle management

## What This Project Does NOT Provide

This is a protocol parser, not a complete SSH library. It does NOT include:

- Cryptographic operations (key exchange, encryption, signing)
- Network I/O and socket management
- Authentication logic
- Channel management and flow control
- High-level features (shell, port forwarding, SFTP client)

## Quick Start

### Build
```bash
./gradlew build
```

### Parse SSH Messages
```java
// Parse SSH banner
ByteBufferKaitaiStream stream = new ByteBufferKaitaiStream(bytes);
Ssh.IdBanner banner = new Ssh.IdBanner(stream);
banner._read();
System.out.println("Version: " + banner.protoVersion());

// Parse unencrypted packet
Ssh.UnencryptedPacket packet = new Ssh.UnencryptedPacket(stream);
packet._read();
switch (packet.payload().messageType()) {
    case SSH_MSG_KEXINIT:
        Ssh.SshMsgKexinit kexinit = (Ssh.SshMsgKexinit) packet.payload().body();
        System.out.println("KEX algorithms: " + kexinit.kexAlgorithms());
        break;
}

// Parse signature
Ssh.SshSignature sig = new Ssh.SshSignature(sigStream);
sig._read();
if (sig.algorithmName().equals("ssh-ed25519")) {
    Ssh.SshEd25519SignatureBlob blob =
        (Ssh.SshEd25519SignatureBlob) sig.signatureBlob();
    byte[] signature = blob.signature().data();
}
```

See [src/test/java/org/connectbot/sshlib/struct/CaptureTest.java](src/test/java/org/connectbot/sshlib/struct/CaptureTest.java) for more examples.

## Key Files

- `src/main/resources/kaitai/ssh.ksy` - Main SSH protocol specification
- `src/main/resources/kaitai/*.ksy` - Supporting type definitions
- `src/main/sm/SshConnection.sm` - State machine framework (incomplete)
- `src/test/java/CaptureTest.java` - Example usage and testing

## License

Apache License 2.0 - See LICENSE file

## Copyright

Copyright 2019-2025, [Kenny Root](https://github.com/kruton/)
