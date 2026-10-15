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

import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.connectbot.sshlib.SshException
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.security.SecureRandom
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

internal class MlKemKeyExchangeTest {
    @ParameterizedTest
    @EnumSource(MlKemParameterSet::class)
    fun `pure ML-KEM agrees with independent BC and stays default off`(parameter: MlKemParameterSet) {
        val client = MlKemKeyExchange(parameter)
        val pub = client.generateClientKeys()
        val p = if (parameter == MlKemParameterSet.ML_KEM_768) MLKEMParameters.ml_kem_768 else MLKEMParameters.ml_kem_1024
        val server = MLKEMGenerator(SecureRandom()).generateEncapsulated(MLKEMPublicKeyParameters(p, pub))
        try {
            assertContentEquals(encodeSshString(server.secret), client.computeSharedSecret(server.encapsulation))
            for (size in listOf(0, server.encapsulation.size - 1, server.encapsulation.size + 1)) assertFailsWith<SshException> { client.computeSharedSecret(ByteArray(size)) }
            val name = if (parameter == MlKemParameterSet.ML_KEM_768) "mlkem768-sha256" else "mlkem1024-sha384"
            val entry = assertNotNull(KexEntry.fromSshName(name))
            assertTrue(entry.isPostQuantum)
            assertFalse(entry in KexEntry.defaults)
            assertFalse(name in KexEntry.defaultString)
            assertEquals(if (parameter == MlKemParameterSet.ML_KEM_768) "SHA-256" else "SHA-384", client.hashAlgorithm)
        } finally {
            client.zeroize()
            server.destroy()
        }
        assertFailsWith<SshException> { client.computeSharedSecret(ByteArray(parameter.ciphertextSize)) }
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet::class)
    fun `secret remains a 32-byte string including zero or high leading bytes and is erased`(parameter: MlKemParameterSet) {
        for (first in listOf(0, 128)) {
            val secret = ByteArray(32) { it.toByte() }.also { it[0] = first.toByte() }
            val retained = ByteArray(parameter.privateKeySize) { 9 }
            var decapsulated = false
            val provider = object : MlKemProvider by KyberKotlinMlKemProvider(parameter) {
                override fun generateKeyPair() = MlKemKeyPair(ByteArray(parameter.publicKeySize), retained)
                override fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
                    decapsulated = true
                    return secret
                }
            }
            val client = MlKemKeyExchange(parameter, provider)
            client.generateClientKeys()
            assertFailsWith<SshException> { client.computeSharedSecret(ByteArray(1)) }
            assertFalse(decapsulated)
            val expected = encodeSshString(secret.copyOf())
            assertContentEquals(expected, client.computeSharedSecret(ByteArray(parameter.ciphertextSize)))
            assertTrue(secret.all { it == 0.toByte() })
            client.generateClientKeys()
            assertTrue(retained.all { it == 0.toByte() })
            client.zeroize()
        }
    }
}
