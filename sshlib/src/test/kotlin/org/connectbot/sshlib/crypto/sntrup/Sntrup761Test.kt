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

package org.connectbot.sshlib.crypto.sntrup

import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator
import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.security.SecureRandom
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor as BcExtractor
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters as BcKeyGenerationParameters
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator as BcKeyPairGenerator
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters as BcParameters
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters as BcPrivateKey
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters as BcPublicKey

class Sntrup761Test {
    private fun random(seed: Int) = SecureRandom.getInstance("SHA1PRNG").apply {
        setSeed(byteArrayOf(seed.toByte()))
    }

    @ParameterizedTest
    @ValueSource(ints = [0, 1, 2, 127, 255])
    fun `extracted key generation and decapsulation match BC including invalid ciphertext fallback`(seed: Int) {
        val generator = SNTRUPrimeKeyPairGenerator()
        generator.init(SNTRUPrimeKeyGenerationParameters(random(seed), SNTRUPrimeParameters.sntrup761))
        val actual = generator.generateKeyPair()
        val actualPublic = actual.getPublic() as SNTRUPrimePublicKeyParameters
        val actualPrivate = actual.getPrivate() as SNTRUPrimePrivateKeyParameters

        val bcGenerator = BcKeyPairGenerator()
        bcGenerator.init(BcKeyGenerationParameters(random(seed), BcParameters.sntrup761))
        val expected = bcGenerator.generateKeyPair()
        val expectedPublic = expected.getPublic() as BcPublicKey
        val expectedPrivate = expected.getPrivate() as BcPrivateKey
        assertEquals(1158, actualPublic.encoded.size)
        assertEquals(1763, actualPrivate.encoded.size)
        assertContentEquals(expectedPublic.encoded, actualPublic.encoded)
        assertContentEquals(expectedPrivate.encoded, actualPrivate.encoded)

        val encapsulated = SNTRUPrimeKEMGenerator(random(seed + 10)).generateEncapsulated(expectedPublic)
        try {
            assertEquals(1039, encapsulated.encapsulation.size)
            val extracted = SNTRUPrimeKEMExtractor(actualPrivate)
            val bc = BcExtractor(expectedPrivate)
            assertContentEquals(encapsulated.secret, extracted.extractSecret(encapsulated.encapsulation))
            // Exercise both the polynomial body and the confirmation-hash portion.
            for (offset in listOf(0, 1006, 1007, 1038)) {
                val damaged = encapsulated.encapsulation.also { it[offset] = (it[offset].toInt() xor 1).toByte() }
                val rejected = extracted.extractSecret(damaged)
                assertContentEquals(bc.extractSecret(damaged), rejected)
                assertFalse(encapsulated.secret.contentEquals(rejected))
            }
        } finally {
            encapsulated.destroy()
            actualPrivate.clear()
        }
        assertTrue(actualPrivate.encoded.all { it == 0.toByte() })
    }

    @Test
    fun `adapter rejects wrong length ciphertext and cannot use cleared keys`() {
        val keys = Sntrup761KeyPair.generate(random(3))
        for (size in listOf(0, 1038, 1040)) {
            assertFailsWith<SshException> { keys.decapsulate(ByteArray(size)) }
        }
        keys.clear()
        keys.clear()
        assertFailsWith<SshException> { keys.decapsulate(ByteArray(1039)) }
    }
}
