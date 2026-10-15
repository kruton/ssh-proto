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

import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.protocol.SshEnums
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SntrupConnectionConformanceTest {
    companion object {
        @JvmStatic
        fun malformedReplies(): List<Arguments> = listOf("sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com").flatMap { algorithm ->
            listOf("short", "long", "zero-point", "low-order", "ciphertext").map { damage -> Arguments.of(algorithm, damage) }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"])
    fun `hybrids authenticate and rekey with independent BC server`(algorithm: String) = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher).apply { kexAlgorithms = algorithm }
        server.start()
        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean = true
            },
            kexAlgorithms = algorithm,
            coroutineDispatcher = dispatcher,
        )
        try {
            val connect = backgroundScope.async(dispatcher) { connection.connect() }
            assertIs<ConnectResult.Success>(withTimeout(5000) { connect.await() })
            assertEquals(algorithm, connection.connectionInfo?.kexAlgorithm)
            assertTrue(connection.connectionInfo!!.isPostQuantumSecure)
            val auth = backgroundScope.async(dispatcher) { connection.authenticatePassword("user", "pass") }
            withTimeout(5000) { server.awaitUserauthRequest() }
            server.sendUserauthSuccess()
            assertIs<AuthResult.Success>(withTimeout(5000) { auth.await() })
            server.initiateRekey()
            withTimeout(5000) { server.rekeyCount.first { it > 0 } }
            val session = backgroundScope.async(dispatcher) { connection.openSessionChannel() }
            val open = withTimeout(5000) { server.awaitChannelOpen() }
            server.sendChannelOpenConfirmation(open.senderChannel().toInt(), 42)
            assertNotNull(withTimeout(5000) { session.await() }).close()
        } finally {
            connection.close()
        }
    }

    @ParameterizedTest
    @MethodSource("malformedReplies")
    fun `malformed replies disconnect before host verification`(algorithm: String, damage: String) = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val ciphertextSize = 1039
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher).apply {
            kexAlgorithms = algorithm
            transformKexServerPublic = { reply ->
                when (damage) {
                    "short" -> reply.copyOf(reply.size - 1)

                    "long" -> reply.copyOf(reply.size + 1)

                    "zero-point" -> reply.copyOf().also { it.fill(0, ciphertextSize, it.size) }

                    "low-order" -> reply.copyOf().also {
                        it.fill(0, ciphertextSize, it.size)
                        it[ciphertextSize] = 1
                    }

                    "ciphertext" -> reply.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

                    else -> error("Unknown damage")
                }
            }
        }
        server.start(ignoreTransportErrors = true)
        var verifierCalled = false
        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean {
                    verifierCalled = true
                    return true
                }
            },
            kexAlgorithms = algorithm,
            coroutineDispatcher = dispatcher,
        )
        try {
            val connect = backgroundScope.async(dispatcher) { connection.connect() }
            assertIs<ConnectResult.ProtocolError>(withTimeout(5000) { connect.await() })
            val disconnect = withTimeout(5000) { server.awaitDisconnect() }
            assertEquals(SshEnums.DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, disconnect.reasonCode())
            assertFalse(verifierCalled)
        } finally {
            connection.close()
        }
    }
}
