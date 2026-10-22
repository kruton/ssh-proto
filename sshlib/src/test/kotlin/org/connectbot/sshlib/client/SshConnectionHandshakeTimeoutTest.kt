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

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.transport.PipedTransport
import org.connectbot.sshlib.transport.Transport
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs

@OptIn(ExperimentalCoroutinesApi::class)
class SshConnectionHandshakeTimeoutTest {
    @Test
    fun `default deadline still expires after thirty seconds`() = runTest {
        val connection = slowConnection().first
        try {
            val result = async { connection.connect() }
            runCurrent()
            advanceTimeBy(29_999)
            runCurrent()
            assertFalse(result.isCompleted)
            advanceTimeBy(1)
            runCurrent()
            assertEquals("Connection timed out", assertIs<ConnectResult.TransportError>(result.await()).cause.message)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `custom deadline allows a slow handshake to finish`() = runTest {
        val connection = slowConnection().first.apply { handshakeTimeoutMs = 120_000 }
        try {
            assertIs<ConnectResult.Success>(connection.connect())
        } finally {
            connection.close()
        }
    }

    @Test
    fun `zero deadline waits beyond default and still completes`() = runTest {
        val connection = slowConnection().first.apply { handshakeTimeoutMs = 0 }
        try {
            val result = async { connection.connect() }
            runCurrent()
            advanceTimeBy(30_001)
            runCurrent()
            assertFalse(result.isCompleted)
            assertIs<ConnectResult.Success>(result.await())
        } finally {
            connection.close()
        }
    }

    @Test
    fun `unlimited handshake still fails on a transport error`() = runTest {
        val connection = slowConnection(fail = true).first.apply { handshakeTimeoutMs = 0 }
        try {
            assertIs<ConnectResult.TransportError>(connection.connect())
        } finally {
            connection.close()
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [0, 120_000])
    fun `caller timeout is propagated and closes the transport`(timeoutMs: Long) = runTest {
        val (connection, transport) = slowConnection()
        connection.handshakeTimeoutMs = timeoutMs
        assertFailsWith<TimeoutCancellationException> {
            withTimeout(1_000) { connection.connect() }
        }
        assertFalse(transport.isConnected)
        connection.close()
    }

    private fun TestScope.slowConnection(fail: Boolean = false): Pair<SshConnection, Transport> {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        // Exchange banners immediately, then delay receiving the first binary packet.
        val slowClientTransport = object : Transport by clientTransport {
            private var bannerReceived = false
            private var delayed = false
            override suspend fun read(count: Int): ByteArray {
                if (bannerReceived && !delayed) {
                    delayed = true
                    delay(60_000)
                    if (fail) throw java.io.IOException("Simulated transport failure")
                }
                return clientTransport.read(count).also {
                    if (!bannerReceived && it.last() == '\n'.code.toByte()) bannerReceived = true
                }
            }
        }
        FakeSshServer(serverTransport, backgroundScope, dispatcher).start(ignoreTransportErrors = true)
        val connection = SshConnection(
            transport = slowClientTransport,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            },
            coroutineDispatcher = dispatcher,
        )
        return connection to slowClientTransport
    }
}
