# Internal Implementation Reference

This file covers architecture details, protocol serialization, concurrency rules, and coding
guidelines for agents working on the internal implementation of the SSH library.

## Algorithm Registry (`Algorithms.kt`)

All supported cryptographic algorithms are declared in enum registries. **Visibility is strictly managed** to limit the public API.

- **`CipherEntry`**, **`MacEntry`**, **`KexEntry`**: Public enums for choosing algorithms, but their `create()` factory methods are `internal`.
- **`SignatureEntry`**: Public enum for host key algorithms. The underlying `algorithm` property is `internal`.
- **Interfaces**: `PacketMac`, `KexAlgorithm`, `PacketCipher`, `PacketAead`, `X25519Provider`, and `SshSignatureAlgorithm` are all `internal`.

**To add a new algorithm**: add an enum entry in `Algorithms.kt`. `SshConnection` and `SshClientConfig` consume the registries.

## Host Key Updates

- `HostKeyUpdateStateMachine` accepts one `hostkeys-00@openssh.com` advertisement
  after authentication. Unknown, disabled, and unavailable algorithms are skipped.
- The client requests proofs for all supported advertised keys, including ML-DSA
  and composite keys. `HostKeyProof.kt` checks the entire ordered reply against the
  initial session identifier and each exact key blob before invoking persistence.
- Global request replies use a bounded FIFO shared with remote forwarding. A
  cancelled or timed-out request retains its slot until its wire reply arrives.
- Proof processing and `HostKeyVerifier.addKeys` / `removeKeys` run outside the
  protocol owner. Updates time out after 30 seconds. Only the authenticated key
  is retired when omitted; other previously stored keys are not enumerated.
- Persistence is optional: read-only verifiers, including `KnownHostsVerifier`,
  keep the default no-op update hooks.

## Code Generation Pipeline

**Kaitai Struct Compiler**: Generates Java classes from `.ksy` protocol definitions.
- Module: `:protocol`
- Input: `protocol/src/main/resources/kaitai/*.ksy`
- Output: `protocol/build/generated/kaitai/org/connectbot/sshlib/protocol/`
- The `kaitai` task automatically runs before compilation.

## State Machine (`SshClientStateMachine.kt`)

Implements SSH client connection lifecycle using KStateMachine.
- **Internal Visibility**: The state machine and its `SshClientCallbacks` are `internal`.
- **Refactored SshConnection**: `SshConnection` no longer implements `SshClientCallbacks` publicly. It uses a private inner object to handle state machine callbacks, ensuring protocol-level types (like `IdBanner` or `SshMsgKexinit`) do not leak into the public API.

## Kaitai Struct Usage

Generated classes are in package `org.connectbot.sshlib.protocol`.

### Reading (parsing)

```kotlin
val stream = ByteBufferKaitaiStream(byteArray)
val message = SomeSshMessage(stream)
message._read()
val field = message.someField()
```

- `readU4be()` → `Long` (unsigned 32-bit big-endian)
- `readBytes(len: Long)` → `ByteArray`
- `readU1()` → `Int`

### Writing (serializing)

Allocate a writable stream with `ByteBufferKaitaiStream(capacityLong)`:

```kotlin
val stream = ByteBufferKaitaiStream(4L + payload.size)
stream.writeU4be(totalLength)   // 4-byte big-endian length
stream.writeU1(messageType)     // 1-byte message type
stream.writeBytes(payload)
stream.seek(0)
return stream.readBytesFull()
```

Key write methods on `KaitaiStream`:
- `writeU4be(Long)` — 4-byte big-endian unsigned int
- `writeU1(Int)` — 1-byte unsigned
- `writeBytes(ByteArray)` — raw bytes
- `writeS4be(Int)` — 4-byte big-endian signed int

### Serializing Kaitai structs

Use the `toByteArray()` extension from `KaitaiUtils.kt`:

```kotlin
val msg = SomeSshMessage()
msg.setField(createByteString(data))
msg._check()
val bytes = msg.toByteArray()
```

### Helper constructors

- `createByteString(ByteArray)` — wraps a byte array as a Kaitai ByteString field
- `createAsciiString(String)` — wraps an ASCII string
- `createUtf8String(String)` — wraps a UTF-8 string

### AsciiString size limit

Kaitai's `AsciiString` validates that the string is ≤ 65535 bytes. Do not use it for arbitrary-length binary blobs (e.g., public key blobs). Use `ByteString` instead.

## Coding Guidelines

- **API Surface**: Keep the public API surface minimal. Use `internal` visibility for all classes and interfaces that deal with protocol-level details (Kaitai structs, state machine callbacks, low-level crypto interfaces).
- **No Unchecked Exceptions**: No unchecked exceptions should be thrown in the library.

### Testability Patterns

- Pure logic extracted to top-level `internal fun` is directly unit-testable without annotation libraries.
- Follow the `selectPasswordMethods`, `keyBlobAlgorithmName`, `buildAgentMessage`, and `isConstraintSatisfied` patterns: extract from class body, pass state as parameters.
- Use `EqualsVerifier.forClass(Foo::class.java).verify()` to unit test `hashCode`/`equals` on any class that implements them.
- `data class` types with `ByteArray` fields need `EqualsVerifier.withPrefabValues(ByteArray::class.java, ...)`.
- Avoid `private` extension functions on `ByteArray?` inside `data class` — they cause `StackOverflowError` with EqualsVerifier. Use `contentEquals()` directly on non-null receivers.

## Concurrency Rules

This codebase has a carefully designed concurrency model. Violating these rules introduces
races, deadlocks, or thread starvation.

**Connection protocol decisions have one owner:**
- `ProtocolExecutor` processes a bounded mailbox sequentially. Enter it before taking a channel
  lifecycle lock. `limitedParallelism(1)` confines shared writer bookkeeping between suspension
  points; it is not the mechanism that serializes complete protocol operations.
- KStateMachine still checks every transition and authorizes every packet. Its pending-event
  handler throws: `PENDING` is never authorization. The state-machine mutexes remain a defensive
  boundary for standalone use and tests.
- Transition callbacks register pending replies and enqueue immutable packet effects. `DeferredIo`
  collects write receipts; local callers await them after leaving the owner and lifecycle locks.
  Inbound processing waits for decisions, not outbound writes. Never await a peer reply or channel
  window credit inside the owner.
- A write receipt means `Transport.write` returned, not that the remote application processed the
  data. Connection close aborts outstanding work; it does not drain writes. Await the write before
  closing for local send completion, and await an application response when remote processing
  matters. Automatic disconnect after the last channel closes waits outside the owner for
  the final DISCONNECT receipt, bounded to five seconds; explicit connection close still aborts.
- Byte-limit rekey checks run in the owner without local admission permits or write waits.
  The packet reader drains buffered packets before triggering another exchange.
- Session and forwarding delivery use per-channel `ChannelDelivery` scopes, tracked by the
  connection's resource ledger independently of packet routing. Remote CLOSE seals ingress and
  retains unread output through network shutdown. Drain completion retires delivery; explicit
  session close or client disconnect aborts it, clears queues, and releases all retained workers.
  Network shutdown never waits for consumers. Explicit connection close joins delivery outside
  the protocol owner. Lazy buffered stdout adapters use delivery ownership too.
- Outbound window-credit admission is a channel-state-machine operation, allowed only while the
  peer can still send data. A write receipt admitted before remote CLOSE may fail during automatic
  teardown without invalidating the retained tail; failures on open channels still fail transport.
- `PacketWriter` is the sole binary packet writer. Its bounded ordinary queue and reserved control
  capacity preserve KEX progress under backpressure. Local admission is bounded separately so
  packet input and shutdown can always enter the owner. Exhausting protocol-generated output
  capacity terminates the transport rather than allocating an unbounded queue.
- Local channel commands arriving during rekey wait outside the owner, then run their normal
  state-machine guards. Cancellation before admission skips the command. Once admitted, a write
  is not retracted: its pending reply slot remains until the peer replies or the connection ends.
- `WaitHostKey` is explicit in KStateMachine. Host verification runs outside the owner and returns
  through `HostKeyVerified`. The reader waits outside the owner for that decision before reading
  the next packet. Outbound protection switches only after the NEWKEYS write completes; inbound
  protection switches before the next packet is read. Each direction owns its staged protection.
- Keep pending authentication, channel requests, global requests, and authentication-method
  bookkeeping in `protocolExecutor.run`. Register a reply and schedule its packet in one operation.
- SFTP serializes request framing with its write mutex, but releases its lifecycle lock before
  writing or waiting for SSH window credit. This lets response processing and disconnect proceed.
- Each remote-forwarder registration owns its pending handler coroutines. Unregistering cancels
  them; cancellation after confirmation admission closes the channel rather than rejecting the open.

**Never use `runBlocking` inside coroutine code:**
- `processNextPacket` and all its callees are `suspend`. Call `suspend` functions directly.
- State machine callbacks that do I/O are declared `suspend` in `SshClientCallbacks`.
- `BlockingSshClient` is the only legitimate use of `runBlocking` — it is the intentional
  blocking adapter at the edge of the system.

**Channel and map thread safety:**
- All four channel maps (`channels`, `channelsByRemote`, `agentChannels`,
  `agentChannelsByRemote`) use `ConcurrentHashMap`. Use `ConcurrentHashMap` for any new
  shared mutable maps accessed from both the packet loop and the caller's coroutine.
- Use `Collections.synchronizedSet` (or `ConcurrentHashMap.newKeySet()`) for any shared
  mutable sets accessed from multiple coroutines.

**Window flow control:**
- Never busy-wait with `delay(N)` for window availability. Use the `Channel<Unit>(CONFLATED)`
  pattern: `windowAvailable.trySend(Unit)` in `onWindowAdjust`, `windowAvailable.receive()`
  in the send loop. Close the channel in the close path to unblock blocked senders.
- `remoteWindowSize` must be `@Volatile` because it is written by `onWindowAdjust` (packet
  loop coroutine) and read by send functions (caller's coroutine).

**`PendingValue<T>` contract:**
- `set(deferred)` — `suspend`, enters the owner, safe from any context.
- `setDirect(deferred)` — non-`suspend`, must be called from within the protocol owner.
- `complete(value)` — non-`suspend`, must be called from within the protocol owner;
  returns `Boolean` (true if a deferred was present).
- `completeExceptionally(e)` — non-`suspend`, must be called from within the protocol owner.
- `clearIfSame(expected)` — `suspend`, safe from any context; use in `finally` blocks to
  remove completed slots only. Cancelling a caller does not remove an outstanding wire reply slot.
