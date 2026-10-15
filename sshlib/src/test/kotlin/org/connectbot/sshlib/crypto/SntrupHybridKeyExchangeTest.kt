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

import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters
import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SntrupHybridKeyExchangeTest {
    private val privateKey = ByteArray(32) { 7 }
    private val serverPublic = ByteArray(32) { 9 }

    private fun classical(secret: ByteArray = ByteArray(32) { 5 }) = object : X25519Provider {
        override fun generatePrivateKey(): ByteArray = privateKey.clone()
        override fun publicFromPrivate(privateKey: ByteArray): ByteArray = ByteArray(32) { 11 }
        override fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
            assertContentEquals(serverPublic, publicKey)
            return secret.clone()
        }
    }

    @ParameterizedTest
    @ValueSource(ints = [0, 128])
    fun `BC server produces the same RFC 9941 shared secret preserving X25519 leading bytes`(first: Int) {
        val ecSecret = ByteArray(32) { it.toByte() }.also { it[0] = first.toByte() }
        val kex = SntrupHybridKeyExchange(classical(ecSecret))
        try {
            val client = kex.generateClientKeys()
            assertEquals(1190, client.size)
            assertContentEquals(ByteArray(32) { 11 }, client.copyOfRange(1158, 1190))
            val serverKey = SNTRUPrimePublicKeyParameters(SNTRUPrimeParameters.sntrup761, client.copyOfRange(0, 1158))
            val encapsulated = SNTRUPrimeKEMGenerator(SecureRandom()).generateEncapsulated(serverKey)
            try {
                val expected = byteArrayOf(0, 0, 0, 64) + MessageDigest.getInstance("SHA-512").digest(encapsulated.secret + ecSecret)
                val actual = kex.computeSharedSecret(encapsulated.encapsulation + serverPublic)
                assertContentEquals(expected, actual)
                assertEquals(68, actual.size)
                assertEquals("SHA-512", kex.hashAlgorithm)
            } finally {
                encapsulated.destroy()
            }
        } finally {
            kex.zeroize()
        }
    }

    @ParameterizedTest
    @ValueSource(ints = [0, 1070, 1072])
    fun `wrong length reply is rejected before X25519`(size: Int) {
        var called = false
        val provider = object : X25519Provider by classical() {
            override fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
                called = true
                return ByteArray(32) { 1 }
            }
        }
        val kex = SntrupHybridKeyExchange(provider)
        try {
            kex.generateClientKeys()
            assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(size)) }
            assertTrue(!called)
        } finally {
            kex.zeroize()
        }
    }

    @ParameterizedTest
    @ValueSource(ints = [0, 31, 32, 33])
    fun `invalid or all-zero X25519 secret is rejected`(size: Int) {
        val kex = SntrupHybridKeyExchange(classical(ByteArray(size)))
        try {
            kex.generateClientKeys()
            assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(1039) + serverPublic) }
        } finally {
            kex.zeroize()
        }
    }

    @Test
    fun `zeroize erases retained X25519 private bytes and makes KEX unusable`() {
        val retained = privateKey.clone()
        val provider = object : X25519Provider by classical() {
            override fun generatePrivateKey(): ByteArray = retained
        }
        val kex = SntrupHybridKeyExchange(provider)
        assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(1071)) }
        kex.generateClientKeys()
        kex.zeroize()
        kex.zeroize()
        assertTrue(retained.all { it == 0.toByte() })
        assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(1071)) }
    }

    @ParameterizedTest
    @ValueSource(strings = ["sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"])
    fun `both registered names use the hybrid implementation and precede classical defaults`(name: String) {
        val entry = KexEntry.fromSshName(name)!!
        assertIs<SntrupHybridKeyExchange>(entry.create())
        assertEquals(KexType.ECDH, entry.type)
        assertTrue(entry.isPostQuantum)
        assertTrue(KexEntry.defaults.indexOf(entry) < KexEntry.defaults.indexOf(KexEntry.CURVE25519_SHA256))
    }

    @Test
    fun `X25519 key generation failure erases private bytes and clears partial KEX state`() {
        val retained = privateKey.clone()
        val provider = object : X25519Provider by classical() {
            override fun generatePrivateKey(): ByteArray = retained
            override fun publicFromPrivate(privateKey: ByteArray): ByteArray = throw java.security.InvalidKeyException("test failure")
        }
        val kex = SntrupHybridKeyExchange(provider)
        assertFailsWith<SshException> { kex.generateClientKeys() }
        assertTrue(retained.all { it == 0.toByte() })
        assertFailsWith<SshException> { kex.computeSharedSecret(ByteArray(1071)) }
    }
}
