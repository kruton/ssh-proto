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

package org.connectbot.sshlib.crypto

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.protocol.GlobalRequestHostkeys00Openssh
import org.connectbot.sshlib.protocol.GlobalRequestHostkeysProve00Openssh
import org.connectbot.sshlib.protocol.GlobalRequestResponseHostkeysProve00Openssh
import org.connectbot.sshlib.protocol.SshMsgGlobalRequest
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import java.security.KeyPairGenerator
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@ResourceLock("JCA_PROVIDERS")
internal class HostKeysProtocolTest {
    private fun request(name: String, wantReply: Boolean, body: ByteArray): ByteArray = encodeSshString(name.toByteArray()) + byteArrayOf(if (wantReply) 1 else 0) + body

    private fun parseRequest(bytes: ByteArray) = SshMsgGlobalRequest(ByteBufferKaitaiStream(bytes)).apply { _read() }

    @Test
    fun `mixed classical and PQC host key announcements and proofs round trip`() = withMldsaTestProvider { provider ->
        val parameters = MldsaAlgorithm.entries
        val pairs = listOf(KeyPairGenerator.getInstance("Ed25519").generateKeyPair()) +
            parameters.map { KeyPairGenerator.getInstance(it.jcaName, provider).generateKeyPair() }
        val keys = pairs.map { SshSigning.encodePublicKey(it) }
        val keyList = keys.fold(byteArrayOf()) { bytes, key -> bytes + encodeSshString(key.publicKeyBlob) }
        val announcementBytes = request("hostkeys-00@openssh.com", false, keyList)
        val announcement = parseRequest(announcementBytes)
        val announcedKeys = (announcement.requestSpecificFields() as GlobalRequestHostkeys00Openssh).hostkeys()
        assertEquals(keys.size, announcedKeys.size)
        keys.zip(announcedKeys).forEach { (key, parsed) -> assertContentEquals(key.publicKeyBlob, parsed.data()) }
        assertContentEquals(announcementBytes, announcement.toByteArray(announcementBytes.size.toLong()))

        val proofRequestBytes = request("hostkeys-prove-00@openssh.com", true, keyList)
        val proofRequest = parseRequest(proofRequestBytes)
        val requestedKeys = (proofRequest.requestSpecificFields() as GlobalRequestHostkeysProve00Openssh).hostkeys()
        assertEquals(keys.size, requestedKeys.size)
        keys.zip(requestedKeys).forEach { (key, parsed) -> assertContentEquals(key.publicKeyBlob, parsed.data()) }
        assertContentEquals(proofRequestBytes, proofRequest.toByteArray(proofRequestBytes.size.toLong()))

        val sessionId = ByteArray(32) { it.toByte() }

        // OpenSSH signs three SSH strings, including the extension name as a domain separator.
        fun proofData(session: ByteArray, key: ByteArray) = encodeSshString("hostkeys-prove-00@openssh.com".toByteArray()) +
            encodeSshString(session) + encodeSshString(key)
        val signatures = pairs.zip(keys).map { (pair, key) ->
            SshSigning.signWithKeyPair(key.algorithmName, pair, proofData(sessionId, key.publicKeyBlob))
        }
        val replyBytes = signatures.fold(byteArrayOf()) { bytes, signature -> bytes + encodeSshString(signature) }
        val reply = GlobalRequestResponseHostkeysProve00Openssh(ByteBufferKaitaiStream(replyBytes)).apply { _read() }
        assertEquals(keys.size, reply.signatures().size)
        assertContentEquals(replyBytes, reply.toByteArray(replyBytes.size.toLong()))
        keys.zip(reply.signatures()).forEachIndexed { index, (key, signature) ->
            assertContentEquals(signatures[index], signature.data())
            assertTrue(SignatureVerifier.verifyWithKeyType(key.publicKeyBlob, signature.data(), proofData(sessionId, key.publicKeyBlob)))
            assertFalse(SignatureVerifier.verifyWithKeyType(key.publicKeyBlob, signature.data(), proofData(sessionId + 1, key.publicKeyBlob)))
            val otherKey = keys[(index + 1) % keys.size].publicKeyBlob
            assertFalse(SignatureVerifier.verifyWithKeyType(key.publicKeyBlob, signature.data(), proofData(sessionId, otherKey)))
        }
    }

    @Test
    fun `unknown and large key blobs preserve framing`() {
        val unknown = encodeSshString("future-pqc@example.com".toByteArray()) + ByteArray(70000) { it.toByte() }
        val tail = encodeSshString("another-key@example.com".toByteArray())
        val body = encodeSshString(unknown) + encodeSshString(tail)
        for (name in listOf("hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com")) {
            val bytes = request(name, name.contains("prove"), body)
            val parsed = parseRequest(bytes)
            val keys = when (val fields = parsed.requestSpecificFields()) {
                is GlobalRequestHostkeys00Openssh -> fields.hostkeys()
                is GlobalRequestHostkeysProve00Openssh -> fields.hostkeys()
                else -> error("Unexpected request")
            }
            assertEquals(2, keys.size)
            assertContentEquals(unknown, keys[0].data())
            assertContentEquals(tail, keys[1].data())
            assertContentEquals(bytes, parsed.toByteArray(bytes.size.toLong()))
        }
    }

    @Test
    fun `truncated host key and signature lists are rejected`() {
        for (body in listOf(byteArrayOf(0), byteArrayOf(0, 0, 0, 2, 1), byteArrayOf(-1, -1, -1, -1))) {
            for (name in listOf("hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com")) {
                assertFailsWith<RuntimeException> { parseRequest(request(name, false, body)) }
            }
            assertFailsWith<RuntimeException> {
                GlobalRequestResponseHostkeysProve00Openssh(ByteBufferKaitaiStream(body))._read()
            }
        }
    }
}
