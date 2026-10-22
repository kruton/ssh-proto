/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot.sshlib.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.protocol.SshEnums
import org.connectbot.sshlib.transport.PipedTransport
import org.connectbot.sshlib.transport.Transport
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class ConnectionBackpressureTest {
    @Test
    fun `invalid channel data closes the connection without waiting for another packet`() = runTest {
        fixture(ignoreTransportErrors = true) { connection, server, transport ->
            val disconnected = backgroundScope.async { connection.disconnectedFlow.first() }
            runCurrent()
            server.sendChannelData(999, ByteArray(32_768))
            withTimeout(1_000) {
                transport.closed.await()
                val failure = assertNotNull(disconnected.await())
                assertTrue(failure.message.orEmpty().contains("unknown channel"))
            }
        }
    }

    @Test
    fun `unregistering remote forwarder cancels suspended handlers and releases resources`() = runTest {
        fixture { connection, server, _ ->
            val entered = CompletableDeferred<Unit>()
            val released = CompletableDeferred<Unit>()
            connection.registerRemoteForwarder("127.0.0.1:8080") { _, _, _, _, _, _, _ ->
                try {
                    entered.complete(Unit)
                    awaitCancellation()
                } finally {
                    released.complete(Unit)
                }
            }
            server.sendForwardedTcpipChannelOpen(100, "127.0.0.1", 8080, "127.0.0.1", 12345)
            withTimeout(1_000) { entered.await() }
            connection.unregisterRemoteForwarder("127.0.0.1:8080")
            withTimeout(1_000) { released.await() }
            server.sendForwardedTcpipChannelOpen(101, "127.0.0.1", 8080, "127.0.0.1", 12345)
            assertEquals(101L, withTimeout(1_000) { server.awaitChannelOpenFailure() }.recipientChannel())
        }
    }

    @Test
    fun `protocol output exhaustion closes connection and resolves outstanding operations`() = runTest {
        fixture(ignoreTransportErrors = true) { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = false)
            val resize = backgroundScope.async { runCatching { session.resizeTerminal(80, 24, 0, 0) } }
            gate.entered.await()
            val request = backgroundScope.async { runCatching { session.requestShell() } }
            val opening = backgroundScope.async { runCatching { connection.openSessionChannel() } }
            runCurrent()
            repeat(33) { server.sendUnknownPacket() }
            withTimeout(1_000) {
                transport.closed.await()
                assertTrue(resize.await().isFailure)
                assertTrue(request.await().isFailure)
                assertTrue(opening.await().isFailure)
            }
        }
    }

    @Test
    fun `cancelled admitted opens consume late confirmations and close their channels`() = runTest {
        fixture { connection, server, _ ->
            connection.autoDisconnectOnLastChannelClose = false
            for (forwarding in listOf(false, true)) {
                val opening = backgroundScope.async {
                    if (forwarding) connection.openDirectTcpipChannel("localhost", 22, "127.0.0.1", 12345) else connection.openSessionChannel()
                }
                val request = server.awaitChannelOpen()
                opening.cancelAndJoin()
                server.sendChannelOpenConfirmation(request.senderChannel().toInt(), senderChannel = 100)
                withTimeout(1_000) {
                    assertEquals(SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE, server.awaitClosingPacket())
                }
                server.sendChannelClose(request.senderChannel().toInt())
                runCurrent()
            }
            val session = openSession(connection, server)
            server.sendChannelData(session.localChannelNumber, byteArrayOf(7))
            assertContentEquals(byteArrayOf(7), withTimeout(1_000) { session.stdout.receive() })
        }
    }

    @Test
    fun `byte rekey leaves reader available while outbound write is blocked`() = runTest {
        fixture(rekeyBytesLimit = 8_192L, ignoreTransportErrors = true) { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = true)
            val writing = backgroundScope.async { runCatching { session.write(ByteArray(16_384)) } }
            gate.entered.await()
            val blocked = List(15) {
                backgroundScope.async { runCatching { session.resizeTerminal(80, 24, 0, 0) } }
            }
            runCurrent()
            server.sendChannelData(session.localChannelNumber, ByteArray(16_384))
            runCurrent()
            val disconnected = backgroundScope.async { connection.disconnectedFlow.first() }
            runCurrent()
            server.sendDisconnect()
            withTimeout(1_000) { disconnected.await() }
            withTimeout(1_000) { writing.await() }
            withTimeout(1_000) { blocked.forEach { assertTrue(it.await().isFailure) } }
        }
    }

    @Test
    fun `auto disconnect sends channel close and disconnect before transport closes`() = runTest {
        fixture { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = false)
            server.sendChannelClose(session.localChannelNumber)
            runCurrent()
            assertFalse(transport.closed.isCompleted)
            gate.release.complete(Unit)
            withTimeout(1_000) {
                assertEquals(SshEnums.MessageType.SSH_MSG_CHANNEL_CLOSE, server.awaitClosingPacket())
                assertEquals(SshEnums.MessageType.SSH_MSG_DISCONNECT, server.awaitClosingPacket())
                transport.closed.await()
            }
        }
    }

    @Test
    fun `buffered channel data drains before another byte rekey`() = runTest {
        fixture(rekeyBytesLimit = 8_192L) { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = false)
            val resize = backgroundScope.async { session.resizeTerminal(80, 24, 0, 0) }
            gate.entered.await()
            val writing = backgroundScope.async { session.write(ByteArray(16_384)) }
            runCurrent()
            server.initiateRekey()
            runCurrent()
            val first = ByteArray(1_024) { 1 }
            val second = ByteArray(1_024) { 2 }
            server.sendChannelData(session.localChannelNumber, first)
            server.sendChannelData(session.localChannelNumber, second)
            runCurrent()
            // Hold NEWKEYS after delivery so the inbound exchange and its byte
            // counter reset finish before the queued data starts the next epoch.
            val newKeys = transport.pauseNextWrite(afterDelivery = true, skip = 2)
            gate.release.complete(Unit)
            withTimeout(5_000) {
                newKeys.entered.await()
                runCurrent()
                newKeys.release.complete(Unit)
                assertContentEquals(first, session.stdout.receive())
                assertContentEquals(second, session.stdout.receive())
                resize.await()
                writing.await()
                server.sendIgnore()
                server.rekeyCount.first { it >= 2 }
            }
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [100, 5_000])
    fun `auto disconnect times out a stuck final write`(timeoutMs: Long) = runTest {
        fixture(ignoreTransportErrors = true) { connection, server, transport ->
            connection.disconnectTimeoutMs = timeoutMs
            val session = openSession(connection, server)
            transport.pauseNextWrite(afterDelivery = false)
            server.sendChannelClose(session.localChannelNumber)
            runCurrent()
            assertFalse(transport.closed.isCompleted)
            advanceTimeBy(timeoutMs - 1)
            runCurrent()
            assertFalse(transport.closed.isCompleted)
            advanceTimeBy(1)
            runCurrent()
            assertTrue(transport.closed.isCompleted)
        }
    }

    @Test
    fun `unlimited disconnect deadline permits a slow final write`() = runTest {
        fixture(ignoreTransportErrors = true) { connection, server, transport ->
            connection.disconnectTimeoutMs = 0
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = false)
            server.sendChannelClose(session.localChannelNumber)
            runCurrent()
            advanceTimeBy(6_000)
            runCurrent()
            assertFalse(transport.closed.isCompleted)
            gate.release.complete(Unit)
            withTimeout(1_000) { transport.closed.await() }
        }
    }

    @Test
    fun `second rekey can start before first outbound NEWKEYS returns`() = runTest {
        fixture { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = true, skip = 2)
            server.initiateRekey()
            gate.entered.await()
            server.rekeyCount.first { it == 1 }
            server.initiateRekey()
            runCurrent()
            val writing = backgroundScope.async { session.write(byteArrayOf(1, 2, 3)) }
            gate.release.complete(Unit)
            withTimeout(5_000) {
                server.rekeyCount.first { it == 2 }
                writing.await()
                assertContentEquals(byteArrayOf(1, 2, 3), server.awaitChannelData().data().data())
                server.sendChannelData(session.localChannelNumber, byteArrayOf(4, 5))
                assertContentEquals(byteArrayOf(4, 5), session.stdout.receive())
            }
        }
    }

    @Test
    fun `shutdown bypasses local commands waiting for rekey`() = runTest {
        fixture(ignoreTransportErrors = true) { connection, server, transport ->
            val gate = transport.pauseNextWrite(afterDelivery = false)
            server.initiateRekey()
            gate.entered.await()
            val openings = List(20) { backgroundScope.async { runCatching { connection.openSessionChannel() } } }
            runCurrent()
            withTimeout(5_000) { connection.close() }
            withTimeout(5_000) { openings.forEach { assertTrue(it.await().isFailure) } }
        }
    }

    @Test
    fun `cancelling a command waiting for rekey does not send it`() = runTest {
        fixture { connection, server, transport ->
            val gate = transport.pauseNextWrite(afterDelivery = false)
            server.initiateRekey()
            gate.entered.await()
            val opening = backgroundScope.async { connection.openSessionChannel() }
            runCurrent()
            opening.cancelAndJoin()
            gate.release.complete(Unit)
            withTimeout(5_000) { server.rekeyCount.first { it == 1 } }
            assertEquals(null, withTimeoutOrNull(100) { server.awaitChannelOpen() })
            assertNotNull(openSession(connection, server))
        }
    }

    @Test
    fun `cancelled request still consumes its own reply`() = runTest {
        fixture { connection, server, _ ->
            val session = openSession(connection, server)
            val request = backgroundScope.async { session.requestShell() }
            server.awaitChannelRequest()
            request.cancelAndJoin()
            server.sendChannelSuccess(session.localChannelNumber)
            runCurrent()
            val payload = byteArrayOf(8, 9)
            server.sendChannelData(session.localChannelNumber, payload)
            assertContentEquals(payload, withTimeout(5_000) { session.stdout.receive() })
        }
    }

    @Test
    fun `new keys activate independently while outbound NEWKEYS is blocked`() = runTest {
        fixture { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = true, skip = 2)
            server.initiateRekey()
            withTimeout(5_000) { gate.entered.await() }
            withTimeout(5_000) { server.rekeyCount.first { it == 1 } }
            val payload = "encrypted with new inbound keys".encodeToByteArray()
            server.sendChannelData(session.localChannelNumber, payload)
            assertContentEquals(payload, withTimeout(5_000) { session.stdout.receive() })
            val writing = backgroundScope.async { session.write(byteArrayOf(4, 5, 6)) }
            runCurrent()
            assertFalse(writing.isCompleted)
            gate.release.complete(Unit)
            withTimeout(5_000) { writing.await() }
            assertContentEquals(byteArrayOf(4, 5, 6), server.awaitChannelData().data().data())
        }
    }

    @Test
    fun `channel open waits for rekey and is revalidated afterward`() = runTest {
        fixture { connection, server, transport ->
            val gate = transport.pauseNextWrite(afterDelivery = false)
            server.initiateRekey()
            gate.entered.await()
            val opening = backgroundScope.async { connection.openSessionChannel() }
            runCurrent()
            assertFalse(opening.isCompleted)
            gate.release.complete(Unit)
            val request = withTimeout(5_000) { server.awaitChannelOpen() }
            server.sendChannelOpenConfirmation(request.senderChannel().toInt(), senderChannel = 100)
            assertNotNull(withTimeout(5_000) { opening.await() })
        }
    }

    @Test
    fun `close cancels a suspended host key verifier`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (client, peer) = PipedTransport.create()
        val server = FakeSshServer(peer, backgroundScope, dispatcher)
        server.start(ignoreTransportErrors = true)
        val entered = CompletableDeferred<Unit>()
        val never = CompletableDeferred<Boolean>()
        val connection = SshConnection(
            transport = client,
            coroutineDispatcher = dispatcher,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean {
                    entered.complete(Unit)
                    return never.await()
                }
            },
        )
        val connecting = backgroundScope.async { connection.connect() }
        try {
            entered.await()
            withTimeout(5_000) { connection.close() }
            assertFalse(withTimeout(5_000) { connecting.await() } is ConnectResult.Success)
        } finally {
            never.complete(false)
            connection.close()
        }
    }

    @Test
    fun `incoming data progresses while resize write has not returned`() = runTest {
        fixture { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = true)
            val resize = backgroundScope.async { session.resizeTerminal(100, 40, 0, 0) }
            gate.entered.await()
            val payload = "output while resize is blocked".encodeToByteArray()
            server.sendChannelData(session.localChannelNumber, payload)
            assertContentEquals(payload, withTimeout(5_000) { session.stdout.receive() })
            gate.release.complete(Unit)
            assertTrue(resize.await())
        }
    }

    @Test
    fun `incoming data progresses while another channel is opening`() = runTest {
        fixture { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = false)
            val opening = backgroundScope.async { connection.openSessionChannel() }
            gate.entered.await()
            val payload = byteArrayOf(1, 2, 3)
            server.sendChannelExtendedData(session.localChannelNumber, 1, payload)
            assertContentEquals(payload, withTimeout(5_000) { session.stderr.receive() })
            gate.release.complete(Unit)
            val request = server.awaitChannelOpen()
            server.sendChannelOpenConfirmation(request.senderChannel().toInt(), senderChannel = 101)
            assertNotNull(opening.await())
        }
    }

    @Test
    fun `close interrupts a transport write without waiting for its lock`() = runTest {
        fixture { connection, server, transport ->
            val session = openSession(connection, server)
            val gate = transport.pauseNextWrite(afterDelivery = false)
            val resize = backgroundScope.async { runCatching { session.resizeTerminal(100, 40, 0, 0) } }
            gate.entered.await()
            // Rescue the old non-cancellable close path after the assertion's deadline.
            backgroundScope.launch {
                delay(6_000)
                gate.release.complete(Unit)
            }
            withTimeout(5_000) { connection.close() }
            assertTrue(withTimeout(5_000) { resize.await() }.isFailure)
        }
    }

    private suspend fun TestScope.openSession(connection: SshConnection, server: FakeSshServer): SessionChannel {
        val opening = backgroundScope.async { connection.openSessionChannel() }
        val request = server.awaitChannelOpen()
        server.sendChannelOpenConfirmation(request.senderChannel().toInt(), senderChannel = 100)
        return assertNotNull(opening.await())
    }

    private suspend fun TestScope.fixture(ignoreTransportErrors: Boolean = false, rekeyBytesLimit: Long = Long.MAX_VALUE, block: suspend TestScope.(SshConnection, FakeSshServer, PausedTransport) -> Unit) {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (client, peer) = PipedTransport.create()
        val transport = PausedTransport(client)
        val server = FakeSshServer(peer, backgroundScope, dispatcher)
        server.start(ignoreTransportErrors = ignoreTransportErrors)
        val connection = SshConnection(
            transport = transport,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            },
            coroutineDispatcher = dispatcher,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = rekeyBytesLimit,
        )
        try {
            assertIs<ConnectResult.Success>(connection.connect())
            val auth = backgroundScope.async { connection.authenticatePassword("user", "pass") }
            server.awaitUserauthRequest()
            server.sendUserauthSuccess()
            assertEquals(AuthResult.Success, auth.await())
            block(connection, server, transport)
        } finally {
            transport.releaseAll()
            connection.close()
        }
    }

    private class PausedTransport(private val delegate: Transport) : Transport by delegate {
        val closed = CompletableDeferred<Unit>()

        override suspend fun close() {
            delegate.close()
            closed.complete(Unit)
        }

        class Gate(val afterDelivery: Boolean) {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
        }
        private var next: Gate? = null
        private var skip = 0
        private val gates = mutableListOf<Gate>()

        fun pauseNextWrite(afterDelivery: Boolean, skip: Int = 0): Gate = Gate(afterDelivery).also {
            check(next == null)
            next = it
            this.skip = skip
            gates += it
        }

        fun releaseAll() = gates.forEach { it.release.complete(Unit) }

        override suspend fun write(data: ByteArray) {
            if (skip > 0) {
                skip--
                delegate.write(data)
                return
            }
            val gate = next
            next = null
            if (gate?.afterDelivery == true) delegate.write(data)
            if (gate != null) {
                gate.entered.complete(Unit)
                gate.release.await()
            }
            if (gate?.afterDelivery != true) delegate.write(data)
        }
    }
}
