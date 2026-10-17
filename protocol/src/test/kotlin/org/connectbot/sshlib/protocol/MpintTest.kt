/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

package org.connectbot.sshlib.protocol

import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MpintTest {
    @Test
    fun emptyBodyRepresentsZero() {
        assertEquals(BigInteger.ZERO, mpint().toBigInteger())
    }

    @Test
    fun conversionPreservesTwosComplementSign() {
        assertEquals(BigInteger.valueOf(-128), mpint(0x80).toBigInteger())
        assertEquals(BigInteger.valueOf(128), mpint(0, 0x80).toBigInteger())
    }

    @Test
    fun positiveConversionAcceptsSignPaddedValues() {
        assertEquals(BigInteger.valueOf(128), mpint(0, 0x80).toPositiveBigInteger())
        assertEquals(BigInteger.ONE, mpint(1).toPositiveBigInteger())
    }

    @Test
    fun positiveConversionRejectsZeroAndNegativeValues() {
        for (value in listOf(mpint(), mpint(0), mpint(0x80), mpint(0xff))) {
            assertFailsWith<IllegalArgumentException> { value.toPositiveBigInteger() }
        }
    }

    private fun mpint(vararg bytes: Int) = Mpint().apply {
        setBody(bytes.map { it.toByte() }.toByteArray())
        setLenBody(bytes.size.toLong())
        _check()
    }
}
