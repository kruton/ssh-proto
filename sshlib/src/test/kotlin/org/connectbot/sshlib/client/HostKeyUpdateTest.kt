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
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PingResult
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.crypto.MldsaAlgorithm
import org.connectbot.sshlib.crypto.encodeSshString
import org.connectbot.sshlib.crypto.withMldsaTestProvider
import org.connectbot.sshlib.protocol.GlobalRequestHostkeysProve00Openssh
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import java.security.KeyPair
import java.security.KeyPairGenerator
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
@ResourceLock("JCA_PROVIDERS")
internal class HostKeyUpdateTest {
    private class Recorder : HostKeyVerifier {
        val added = mutableListOf<PublicKey>()
        val removed = mutableListOf<PublicKey>()
        var blockPersistence: CompletableDeferred<Unit>? = null
        override suspend fun verify(key: PublicKey) = true
        override suspend fun addKeys(keys: List<PublicKey>) {
            blockPersistence?.await()
            added.addAll(keys)
        }
        override suspend fun removeKeys(keys: List<PublicKey>) {
            removed.addAll(keys)
        }
    }

    private suspend fun TestScope.fixture(recorder: Recorder, algorithms: String = "ssh-ed25519"): Pair<SshConnection, FakeSshServer> {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (client, remote) = PipedTransport.create()
        val server = FakeSshServer(remote, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
        server.start(ignoreTransportErrors = true)
        val connection = SshConnection(
            transport = client,
            hostKeyVerifier = recorder,
            hostKeyAlgorithms = algorithms,
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = Long.MAX_VALUE,
            coroutineDispatcher = dispatcher,
        )
        assertIs<ConnectResult.Success>(connection.connect())
        val auth = async { connection.authenticatePassword("user", "pass") }
        server.awaitUserauthRequest()
        server.sendUserauthSuccess()
        assertEquals(AuthResult.Success, auth.await())
        return connection to server
    }

    private fun key(pair: KeyPair): PublicKey = SshSigning.encodePublicKey(pair).let { PublicKey(it.algorithmName, it.publicKeyBlob) }
    private fun strings(blobs: List<ByteArray>) = blobs.fold(byteArrayOf()) { result, blob -> result + encodeSshString(blob) }

    // Construct the OpenSSH signed payload independently of the production helper.
    private fun proof(pair: KeyPair, sid: ByteArray, blob: ByteArray): ByteArray = SshSigning.signWithKeyPair(
        key(pair).type,
        pair,
        encodeSshString("hostkeys-prove-00@openssh.com".toByteArray()) + encodeSshString(sid) + encodeSshString(blob),
    )

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `proven PQC key replaces the authenticated classical key`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val newKey = key(pair)
        runTest {
            val recorder = Recorder()
            val (connection, server) = fixture(recorder, "ssh-ed25519,${parameter.sshName}")
            try {
                server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(listOf(newKey.encoded)))
                val request = server.awaitGlobalRequest()
                assertEquals("hostkeys-prove-00@openssh.com", request.requestName().value())
                assertEquals(1, request.wantReply())
                val requested = (request.requestSpecificFields() as GlobalRequestHostkeysProve00Openssh).hostkeys()
                assertEquals(1, requested.size)
                assertContentEquals(newKey.encoded, requested.single().data())
                assertTrue(recorder.added.isEmpty())
                assertTrue(recorder.removed.isEmpty())
                server.sendRequestSuccess(strings(listOf(proof(pair, server.sessionIdentifier, newKey.encoded))))
                runCurrent()
                assertEquals(listOf(newKey), recorder.added)
                assertEquals(listOf(PublicKey("ssh-ed25519", server.serverHostKeyBlob)), recorder.removed)
                // A second announcement must not start another update.
                server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(listOf(newKey.encoded)))
                runCurrent()
                assertEquals(listOf(newKey), recorder.added)
                assertIs<PingResult.Success>(connection.ping())
            } finally {
                connection.close()
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["failure", "missing", "extra", "truncated", "wrong-session", "wrong-key", "reordered", "corrupt"])
    fun `bad proofs never add or retire keys`(mode: String) = runTest {
        val pairs = List(2) { KeyPairGenerator.getInstance("Ed25519").generateKeyPair() }
        val keys = pairs.map(::key)
        val recorder = Recorder()
        val (connection, server) = fixture(recorder)
        try {
            server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(keys.map { it.encoded }))
            server.awaitGlobalRequest()
            val sid = server.sessionIdentifier
            val signatures = pairs.zip(keys).map { (pair, key) -> proof(pair, sid, key.encoded) }
            when (mode) {
                "failure" -> server.sendRequestFailure()
                "missing" -> server.sendRequestSuccess(strings(signatures.take(1)))
                "extra" -> server.sendRequestSuccess(strings(signatures + signatures.first()))
                "truncated" -> server.sendRequestSuccess(strings(signatures).dropLast(1).toByteArray())
                "wrong-session" -> server.sendRequestSuccess(strings(pairs.zip(keys).map { (pair, key) -> proof(pair, sid + 1, key.encoded) }))
                "wrong-key" -> server.sendRequestSuccess(strings(pairs.zip(keys).map { (pair, key) -> proof(pair, sid, key.encoded + 1) }))
                "reordered" -> server.sendRequestSuccess(strings(signatures.reversed()))
                "corrupt" -> server.sendRequestSuccess(strings(signatures.map { it.copyOf().apply { this[lastIndex] = (last().toInt() xor 1).toByte() } }))
            }
            runCurrent()
            assertTrue(recorder.added.isEmpty())
            assertTrue(recorder.removed.isEmpty())
            assertIs<PingResult.Success>(connection.ping())
        } finally {
            connection.close()
        }
    }

    @Test
    fun `proof replies and concurrent forwarding replies retain FIFO ordering`() = runTest {
        val recorder = Recorder()
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val newKey = key(pair)
        val (connection, server) = fixture(recorder)
        try {
            val forward = async { connection.sendTcpipForwardRequest("localhost", 1234) }
            assertEquals("tcpip-forward", server.awaitGlobalRequest().requestName().value())
            server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(listOf(newKey.encoded)))
            assertEquals("hostkeys-prove-00@openssh.com", server.awaitGlobalRequest().requestName().value())
            server.sendRequestSuccess()
            assertEquals(1234, forward.await())
            server.sendRequestSuccess(strings(listOf(proof(pair, server.sessionIdentifier, newKey.encoded))))
            runCurrent()
            assertEquals(listOf(newKey), recorder.added)
            assertIs<PingResult.Success>(connection.ping())
        } finally {
            connection.close()
        }
    }

    @Test
    fun `suspending persistence does not block packet routing or retire keys early`() = runTest {
        val recorder = Recorder().apply { blockPersistence = CompletableDeferred() }
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val newKey = key(pair)
        val (connection, server) = fixture(recorder)
        try {
            server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(listOf(newKey.encoded)))
            server.awaitGlobalRequest()
            server.sendRequestSuccess(strings(listOf(proof(pair, server.sessionIdentifier, newKey.encoded))))
            runCurrent()
            assertIs<PingResult.Success>(connection.ping())
            assertTrue(recorder.removed.isEmpty())
            recorder.blockPersistence!!.complete(Unit)
            runCurrent()
            assertEquals(listOf(newKey), recorder.added)
            assertEquals(1, recorder.removed.size)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `unknown keys are skipped and an advertised authenticated key is retained`() = runTest {
        val recorder = Recorder()
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val newKey = key(pair)
        val (connection, server) = fixture(recorder)
        try {
            val unknown = encodeSshString("future-pqc@example.com".toByteArray()) + byteArrayOf(1, 2, 3)
            server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(listOf(unknown, newKey.encoded, server.serverHostKeyBlob)))
            val request = server.awaitGlobalRequest()
            val requested = (request.requestSpecificFields() as GlobalRequestHostkeysProve00Openssh).hostkeys()
            assertEquals(2, requested.size)
            val signedInitial = server.signHostKeyData(
                encodeSshString("hostkeys-prove-00@openssh.com".toByteArray()) +
                    encodeSshString(server.sessionIdentifier) + encodeSshString(server.serverHostKeyBlob),
            )
            server.sendRequestSuccess(strings(listOf(proof(pair, server.sessionIdentifier, newKey.encoded), signedInitial)))
            runCurrent()
            assertEquals(listOf(newKey, PublicKey("ssh-ed25519", server.serverHostKeyBlob)), recorder.added)
            assertTrue(recorder.removed.isEmpty())
        } finally {
            connection.close()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["empty", "duplicate", "unknown", "disabled", "want-reply"])
    fun `unusable advertisements do not request proofs`(mode: String) = withMldsaTestProvider { provider ->
        runTest {
            val recorder = Recorder()
            val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            val newKey = key(pair)
            val (connection, server) = fixture(recorder)
            try {
                val blobs = when (mode) {
                    "empty" -> emptyList()
                    "duplicate" -> listOf(newKey.encoded, newKey.encoded)
                    "unknown" -> listOf(encodeSshString("unknown@example.com".toByteArray()))
                    "disabled" -> listOf(key(KeyPairGenerator.getInstance("ML-DSA-44", provider).generateKeyPair()).encoded)
                    else -> listOf(newKey.encoded)
                }
                server.sendGlobalRequest("hostkeys-00@openssh.com", mode == "want-reply", strings(blobs))
                runCurrent()
                val forward = async { connection.sendTcpipForwardRequest("localhost", 1234) }
                // If an unwanted proof request was sent, it would be first in the queue.
                assertEquals("tcpip-forward", server.awaitGlobalRequest().requestName().value())
                server.sendRequestSuccess()
                assertEquals(1234, forward.await())
                assertTrue(recorder.added.isEmpty())
                assertTrue(recorder.removed.isEmpty())
            } finally {
                connection.close()
            }
        }
    }

    @Test
    fun `timed out proofs retain their reply slot without persisting keys`() = runTest {
        val recorder = Recorder()
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val newKey = key(pair)
        val (connection, server) = fixture(recorder)
        try {
            server.sendGlobalRequest("hostkeys-00@openssh.com", false, strings(listOf(newKey.encoded)))
            server.awaitGlobalRequest()
            advanceTimeBy(30_001)
            runCurrent()
            val forward = async { connection.sendTcpipForwardRequest("localhost", 1234) }
            assertEquals("tcpip-forward", server.awaitGlobalRequest().requestName().value())
            server.sendRequestSuccess(strings(listOf(proof(pair, server.sessionIdentifier, newKey.encoded))))
            server.sendRequestSuccess()
            assertEquals(1234, forward.await())
            assertTrue(recorder.added.isEmpty())
            assertTrue(recorder.removed.isEmpty())
        } finally {
            connection.close()
        }
    }
}
