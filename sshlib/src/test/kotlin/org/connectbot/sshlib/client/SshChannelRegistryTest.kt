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

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.protocol.SshChannelState
import org.connectbot.sshlib.protocol.SshChannelStateMachine
import org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SshChannelRegistryTest {
    @Test
    fun `local and remote recipients resolve one established channel`() {
        val registry = SshChannelRegistry()
        val session = sessionChannel(local = 7, remote = 70)

        registry.register(session)

        assertIs<SshChannelRegistry.Entry.Established.Session>(registry.findByLocalRecipient(7))
        assertSame(
            session,
            registry.findByRemoteRecipient(70)?.let {
                (it as SshChannelRegistry.Entry.Established.Session).channel
            },
        )
        assertNull(registry.findByLocalRecipient(8))
        assertNull(registry.findByRemoteRecipient(71))
    }

    @Test
    fun `duplicate local recipient is rejected across channel kinds`() {
        val registry = SshChannelRegistry()
        registry.register(sessionChannel(local = 7, remote = 70))

        assertFailsWith<IllegalStateException> {
            registry.register(forwardingChannel(local = 7, remote = 80))
        }
    }

    @Test
    fun `duplicate remote recipient is rejected across local IDs`() {
        val registry = SshChannelRegistry()
        registry.register(sessionChannel(local = 7, remote = 70))

        assertFailsWith<IllegalStateException> {
            registry.register(forwardingChannel(local = 8, remote = 70))
        }
    }

    @Test
    fun `pending open continuously owns local ID through atomic promotion`() {
        val registry = SshChannelRegistry()
        val deferred = CompletableDeferred<org.connectbot.sshlib.protocol.SshMsgChannelOpenConfirmation?>()
        val lifecycle = SshChannelStateMachine(SshChannelState.OPENING)
        registry.registerPendingSession(7, deferred, lifecycle)
        val pending = registry.findPendingSession(7)!!

        registry.bindRemoteRecipient(pending, 70)
        val session = sessionChannel(local = 7, remote = 70)
        registry.promote(pending, session)

        assertNull(registry.findPendingSession(7))
        assertSame(
            session,
            (registry.findByLocalRecipient(7) as SshChannelRegistry.Entry.Established.Session).channel,
        )
        assertEquals(7, registry.findByRemoteRecipient(70)?.localChannelNumber)
    }

    @Test
    fun `unregister removes local and remote indexes together`() {
        val registry = SshChannelRegistry()
        registry.register(sessionChannel(local = 7, remote = 70))

        registry.unregister(7)

        assertNull(registry.findByLocalRecipient(7))
        assertNull(registry.findByRemoteRecipient(70))
    }

    @Test
    fun `disconnect cascade removes and closes pending and established entries`() = runTest {
        val registry = SshChannelRegistry()
        val session = sessionChannel(local = 7, remote = 70)
        coEvery { session.onDisconnected() } returns Unit
        val pendingDeferred = CompletableDeferred<ForwardingChannel?>()
        registry.register(session)
        registry.registerPendingForwarding(
            localChannelNumber = 8,
            deferred = pendingDeferred,
            maxPacketSize = 32 * 1024,
            initialWindowSize = 64 * 1024,
            lifecycle = SshChannelStateMachine(SshChannelState.OPENING),
        )
        val cause = IllegalStateException("connection lost")

        registry.disconnectAll(cause)

        coVerify(exactly = 1) { session.onDisconnected() }
        assertTrue(registry.snapshot().isEmpty())
        assertNull(registry.findByRemoteRecipient(70))
        assertEquals(cause.message, assertFailsWith<IllegalStateException> { pendingDeferred.await() }.message)
        assertFailsWith<IllegalStateException> {
            registry.register(sessionChannel(local = 9, remote = 90))
        }
    }

    private fun sessionChannel(local: Int, remote: Int) = mockk<SessionChannel> {
        every { localChannelNumber } returns local
        every { remoteChannelNumber } returns remote
        every { isOpen } returns true
    }

    @Test
    fun `binding rejects stale duplicate and already bound entries without changing indexes`() {
        val registry = SshChannelRegistry()
        registry.registerPendingSession(1, CompletableDeferred(), SshChannelStateMachine(SshChannelState.OPENING))
        registry.registerPendingSession(2, CompletableDeferred(), SshChannelStateMachine(SshChannelState.OPENING))
        val first = registry.findPendingSession(1)!!
        val second = registry.findPendingSession(2)!!
        registry.bindRemoteRecipient(first, 10)

        assertFailsWith<IllegalStateException> { registry.bindRemoteRecipient(first, 11) }
        assertFailsWith<IllegalStateException> { registry.bindRemoteRecipient(second, 10) }
        assertEquals(10, first.remoteChannelNumber)
        assertNull(second.remoteChannelNumber)
        registry.unregister(2)
        assertFailsWith<IllegalStateException> { registry.bindRemoteRecipient(second, 20) }
        assertNull(registry.findByRemoteRecipient(20))
        registry.promote(first, sessionChannel(1, 10))
        assertEquals(1, registry.findByRemoteRecipient(10)?.localChannelNumber)
    }

    @Test
    fun `promotion rejects changed recipients and removed entries`() {
        val registry = SshChannelRegistry()
        registry.registerPendingSession(1, CompletableDeferred(), SshChannelStateMachine(SshChannelState.OPENING))
        val pending = registry.findPendingSession(1)!!
        registry.bindRemoteRecipient(pending, 10)
        assertFailsWith<IllegalStateException> { registry.promote(pending, sessionChannel(2, 10)) }
        assertFailsWith<IllegalStateException> { registry.promote(pending, sessionChannel(1, 11)) }
        assertSame(pending, registry.findPendingSession(1))
        registry.unregister(1)
        assertFailsWith<IllegalStateException> { registry.promote(pending, sessionChannel(1, 10)) }
        assertTrue(registry.snapshot().isEmpty())
    }

    @Test
    fun `pending removal requires matching deferred and channel kind`() {
        val registry = SshChannelRegistry()
        val sessionReply = CompletableDeferred<SshMsgChannelOpenConfirmation?>()
        val forwardingReply = CompletableDeferred<ForwardingChannel?>()
        registry.registerPendingSession(1, sessionReply, SshChannelStateMachine(SshChannelState.OPENING))
        registry.registerPendingForwarding(2, forwardingReply, 32768, 65536, SshChannelStateMachine(SshChannelState.OPENING))
        val session = registry.findPendingSession(1)!!
        val forwarding = registry.findPendingForwarding(2)!!
        registry.bindRemoteRecipient(session, 10)
        registry.bindRemoteRecipient(forwarding, 20)

        assertNull(registry.removePendingSessionIf(1, CompletableDeferred()))
        assertNull(registry.removePendingForwardingIf(2, CompletableDeferred()))
        assertNull(registry.removePendingSessionIf(2, sessionReply))
        assertNull(registry.removePendingForwardingIf(1, forwardingReply))
        assertNull(registry.removePendingSessionIf(3, sessionReply))
        assertNull(registry.removePendingForwardingIf(3, forwardingReply))
        assertEquals(2, registry.snapshot().size)
        assertSame(session, registry.removePendingSessionIf(1, sessionReply))
        assertSame(forwarding, registry.removePendingForwardingIf(2, forwardingReply))
        assertTrue(registry.snapshot().isEmpty())
        assertNull(registry.findByRemoteRecipient(10))
        assertNull(registry.findByRemoteRecipient(20))
        assertNull(registry.unregister(1))
    }

    @Test
    fun `forwarding promotion retains recipients and reflects channel liveness`() {
        val registry = SshChannelRegistry()
        registry.registerPendingForwarding(1, CompletableDeferred(), 32768, 65536, SshChannelStateMachine(SshChannelState.OPENING))
        val pending = registry.findPendingForwarding(1)!!
        registry.bindRemoteRecipient(pending, 10)
        assertNull(registry.findByRemoteRecipient(10))
        assertTrue(registry.establishedSnapshot().isEmpty())
        val channel = forwardingChannel(1, 10)
        registry.promote(pending, channel)
        val established = registry.establishedSnapshot().single()
        assertEquals(SshChannelRegistry.Kind.FORWARDING, established.kind)
        assertTrue(established.isOpen)
        every { channel.isOpen } returns false
        assertEquals(false, established.isOpen)
        assertSame(established, registry.findByRemoteRecipient(10))
    }

    @Test
    fun `disconnect continues after channel failure and closes every kind exactly once`() = runTest {
        val registry = SshChannelRegistry()
        val session = sessionChannel(1, 10)
        val forwarding = forwardingChannel(2, 20)
        val agent = mockk<AgentChannel> {
            every { localChannelNumber } returns 3
            every { remoteChannelNumber } returns 30
            every { isOpen } returns true
        }
        val failure = IllegalStateException("session cleanup failed")
        coEvery { session.onDisconnected() } throws failure
        coEvery { forwarding.onDisconnected() } returns Unit
        coEvery { agent.onDisconnected() } returns Unit
        registry.register(session)
        registry.register(forwarding)
        registry.register(agent)
        assertTrue(registry.establishedSnapshot().all { it.isOpen })
        assertEquals(SshChannelRegistry.Kind.AGENT, registry.findByLocalRecipient(3)?.kind)
        val reply = CompletableDeferred<SshMsgChannelOpenConfirmation?>()
        registry.registerPendingSession(4, reply, SshChannelStateMachine(SshChannelState.OPENING))
        val pending = registry.findPendingSession(4)!!
        val cause = IllegalStateException("transport closed")

        registry.disconnectAll(cause)
        registry.disconnectAll(cause)

        assertEquals(listOf(failure), cause.suppressed.toList())
        assertEquals(cause.message, assertFailsWith<IllegalStateException> { reply.await() }.message)
        coVerify(exactly = 1) { session.onDisconnected() }
        coVerify(exactly = 1) { forwarding.onDisconnected() }
        coVerify(exactly = 1) { agent.onDisconnected() }
        assertTrue(registry.snapshot().isEmpty())
        assertFailsWith<IllegalStateException> { registry.bindRemoteRecipient(pending, 40) }
        assertFailsWith<IllegalStateException> { registry.promote(pending, sessionChannel(4, 40)) }
    }

    private fun forwardingChannel(local: Int, remote: Int) = mockk<ForwardingChannel> {
        every { localChannelNumber } returns local
        every { remoteChannelNumber } returns remote
        every { isOpen } returns true
    }
}
