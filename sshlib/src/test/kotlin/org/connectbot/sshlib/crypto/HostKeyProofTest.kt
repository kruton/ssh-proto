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

import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshSigning
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.security.KeyPairGenerator
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@ResourceLock("JCA_PROVIDERS")
internal class HostKeyProofTest {
    private val sessionId = ByteArray(32) { it.toByte() }

    @Test
    fun `RSA proofs use the negotiated SHA2 algorithm and cannot fall back to SHA1`() {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val key = SshSigning.encodePublicKey(pair).let { PublicKey(it.algorithmName, it.publicKeyBlob) }
        val algorithms = setOf("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa")
        for (algorithm in algorithms) {
            val signature = SshSigning.signWithKeyPair(algorithm, pair, hostKeyProofData(sessionId, key.encoded))
            val reply = encodeSshString(signature)
            for (negotiated in algorithms + "ssh-ed25519") {
                val expected = algorithm != "ssh-rsa" && (negotiated == algorithm || negotiated == "ssh-ed25519")
                val valid = verifyHostKeyProofs(listOf(key), reply, sessionId, negotiated, algorithms)
                if (expected) assertTrue(valid) else assertFalse(valid)
            }
            assertFalse(verifyHostKeyProofs(listOf(key), reply, sessionId, "ssh-ed25519", emptySet()))
        }
    }

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `PQC proof validation rejects tampering and trailing bytes`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val key = SshSigning.encodePublicKey(pair).let { PublicKey(it.algorithmName, it.publicKeyBlob) }
        val signature = SshSigning.signWithKeyPair(parameter.sshName, pair, hostKeyProofData(sessionId, key.encoded))
        val allowed = setOf(parameter.sshName)
        fun verify(keys: List<PublicKey>, proof: ByteArray) = verifyHostKeyProofs(keys, proof, sessionId, "ssh-ed25519", allowed)
        assertTrue(verify(listOf(key), encodeSshString(signature)))
        assertFalse(verify(listOf(key), encodeSshString(signature + 0)))
        val trailingKey = key.copy(encoded = key.encoded + 0)
        val trailingKeySignature = SshSigning.signWithKeyPair(parameter.sshName, pair, hostKeyProofData(sessionId, trailingKey.encoded))
        assertFalse(verify(listOf(trailingKey), encodeSshString(trailingKeySignature)))
        val damaged = signature.copyOf().apply { this[lastIndex] = (last().toInt() xor 1).toByte() }
        assertFalse(verify(listOf(key), encodeSshString(damaged)))
        assertFalse(verifyHostKeyProofs(listOf(key), encodeSshString(signature), sessionId, "ssh-ed25519", emptySet()))
    }
}
