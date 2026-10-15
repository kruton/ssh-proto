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

import org.connectbot.sshlib.SshException
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.security.AlgorithmParameters
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.HexFormat
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class MlKemNistHybridKeyExchangeTest {
    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `Kotlin client agrees with independent BC and JCA server`(parameters: MlKemNistParameters) {
        val kex = MlKemNistHybridKeyExchange(parameters, KyberKotlinMlKemProvider(parameters.mlKem))
        try {
            val clientInit = kex.generateClientKeys()
            val is384 = parameters == MlKemNistParameters.NISTP384
            assertEquals(if (is384) 1665 else 1249, clientInit.size)
            val server = NistHybridTestServer.reply(clientInit, is384)
            assertEquals(if (is384) 1665 else 1153, server.reply.size)
            assertContentEquals(server.sharedSecret, kex.computeSharedSecret(server.reply))
            assertEquals(if (is384) "SHA-384" else "SHA-256", kex.hashAlgorithm)
        } finally {
            kex.zeroize()
        }
        assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(0)) }
    }

    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `wrong reply size fails before decapsulation`(parameters: MlKemNistParameters) {
        var decapsulated = false
        val provider = object : MlKemProvider by KyberKotlinMlKemProvider(parameters.mlKem) {
            override fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
                decapsulated = true
                return ByteArray(32)
            }
        }
        val kex = MlKemNistHybridKeyExchange(parameters, provider)
        try {
            kex.generateClientKeys()
            val size = if (parameters == MlKemNistParameters.NISTP384) 1665 else 1153
            for (length in listOf(0, size - 1, size + 1)) {
                assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(length)) }
            }
            assertFalse(decapsulated)
        } finally {
            kex.zeroize()
        }
    }

    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `infinity compressed off-curve and out-of-range points fail before decapsulation`(parameters: MlKemNistParameters) {
        var decapsulated = false
        val provider = object : MlKemProvider by KyberKotlinMlKemProvider(parameters.mlKem) {
            override fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
                decapsulated = true
                return ByteArray(32)
            }
        }
        val kex = MlKemNistHybridKeyExchange(parameters, provider)
        try {
            kex.generateClientKeys()
            val size = parameters.mlKem.ciphertextSize + 1 + 2 * parameters.fieldSize
            for (tag in listOf(0, 2, 4)) {
                val reply = ByteArray(size).also { it[parameters.mlKem.ciphertextSize] = tag.toByte() }
                assertFailsWith<SshException> { kex.computeSharedSecret(reply) }
            }
            val algorithm = AlgorithmParameters.getInstance("EC")
            algorithm.init(ECGenParameterSpec(if (parameters.fieldSize == 32) "secp256r1" else "secp384r1"))
            val spec = algorithm.getParameterSpec(ECParameterSpec::class.java)
            val p = (spec.curve.field as ECFieldFp).p.toByteArray().takeLast(parameters.fieldSize).toByteArray()
            val reply = ByteArray(size).also {
                it[parameters.mlKem.ciphertextSize] = 4
                p.copyInto(it, parameters.mlKem.ciphertextSize + 1)
            }
            assertFailsWith<SshException> { kex.computeSharedSecret(reply) }
            assertFalse(decapsulated)
        } finally {
            kex.zeroize()
        }
    }

    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `fixed width combiner matches independent fixtures with zero and high first byte`(parameters: MlKemNistParameters) {
        val kex = MlKemNistHybridKeyExchange(parameters)
        val pq = ByteArray(32) { (it + 10).toByte() }
        for (first in listOf(0, 128)) {
            val ec = ByteArray(parameters.fieldSize) { it.toByte() }.also { it[0] = first.toByte() }
            val fixture = when (parameters to first) {
                MlKemNistParameters.NISTP256 to 0 -> "0000002085f723f0303811e5b5077b130289be04c47df6e505d5fdbec17caef278d49768"
                MlKemNistParameters.NISTP256 to 128 -> "000000201932f7ce81dfad66450d3b020b995f182c09ae8194e74e8da09d93fcbdd4a829"
                MlKemNistParameters.NISTP384 to 0 -> "0000003014fbb275288b019e61881b4b8e0d0d209e898afc0487475439b20601cb0be03094c76d2fd6f82b78ee186ce12d8e85eb"
                MlKemNistParameters.NISTP384 to 128 -> "00000030e526285afafeb1895b69e9052b14ac7c1c08cf24178d445a8199a7f2669ea18f1011cf24f54c5ee164ec423619240a8f"
                else -> error("Missing fixture")
            }
            assertContentEquals(HexFormat.of().parseHex(fixture), kex.combineSharedSecrets(pq, ec))
        }
    }

    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `combiner rejects variable-width secrets and zero ECDH output`(parameters: MlKemNistParameters) {
        val kex = MlKemNistHybridKeyExchange(parameters)
        val ec = ByteArray(parameters.fieldSize) { 1 }
        for (size in listOf(0, 31, 33)) {
            assertFailsWith<SshException> { kex.combineSharedSecrets(ByteArray(size), ec) }
        }
        for (size in listOf(0, parameters.fieldSize - 1, parameters.fieldSize + 1)) {
            assertFailsWith<SshException> { kex.combineSharedSecrets(ByteArray(32), ByteArray(size) { 1 }) }
        }
        assertFailsWith<SshException> { kex.combineSharedSecrets(ByteArray(32), ByteArray(parameters.fieldSize)) }
    }

    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `regeneration and cleanup erase retained ML-KEM private keys`(parameters: MlKemNistParameters) {
        val retained = mutableListOf<ByteArray>()
        val provider = object : MlKemProvider by KyberKotlinMlKemProvider(parameters.mlKem) {
            override fun generateKeyPair(): MlKemKeyPair = MlKemKeyPair(
                ByteArray(parameters.mlKem.publicKeySize),
                ByteArray(parameters.mlKem.privateKeySize) { 7 }.also { retained.add(it) },
            )
        }
        val kex = MlKemNistHybridKeyExchange(parameters, provider)
        assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(0)) }
        kex.generateClientKeys()
        kex.generateClientKeys()
        assertTrue(retained[0].all { it == 0.toByte() })
        assertTrue(retained[1].any { it != 0.toByte() })
        kex.zeroize()
        kex.zeroize()
        assertTrue(retained[1].all { it == 0.toByte() })
    }

    @ParameterizedTest
    @EnumSource(MlKemNistParameters::class)
    fun `malformed generated ML-KEM key is rejected and erased`(parameters: MlKemNistParameters) {
        val retained = ByteArray(32) { 7 }
        val provider = object : MlKemProvider by KyberKotlinMlKemProvider(parameters.mlKem) {
            override fun generateKeyPair(): MlKemKeyPair = MlKemKeyPair(ByteArray(1), retained)
        }
        val kex = MlKemNistHybridKeyExchange(parameters, provider)
        assertFailsWith<SshException> { kex.generateClientKeys() }
        assertTrue(retained.all { it == 0.toByte() })
        assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(0)) }
    }
}
