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

package org.connectbot.sshlib.crypto

import org.connectbot.sshlib.SshException
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PrivateKeyReaderTest {

    private fun readKey(resourcePath: String): String = javaClass.getResourceAsStream("/keys/$resourcePath")!!
        .bufferedReader().readText()

    // OpenSSH format - Ed25519

    @Test
    fun `reads unencrypted OpenSSH Ed25519 key`() {
        val key = PrivateKeyReader.read(readKey("ed25519_unencrypted"))
        assertEquals("ssh-ed25519", key.keyType)
        assertEquals("ssh-ed25519", key.signatureAlgorithm)
        assertNotNull(key.jcaKeyPair.private)
        assertNotNull(key.jcaKeyPair.public)
    }

    @Test
    fun `reads encrypted OpenSSH Ed25519 key`() {
        val key = PrivateKeyReader.read(readKey("ed25519_encrypted"), "testpass")
        assertEquals("ssh-ed25519", key.keyType)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `rejects encrypted Ed25519 key without passphrase`() {
        assertFailsWith<SshException> {
            PrivateKeyReader.read(readKey("ed25519_encrypted"))
        }
    }

    // OpenSSH format - ECDSA

    @Test
    fun `reads unencrypted OpenSSH ECDSA-256 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa256_unencrypted"))
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
        assertEquals("ecdsa-sha2-nistp256", key.signatureAlgorithm)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `reads encrypted OpenSSH ECDSA-256 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa256_encrypted"), "testpass")
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `reads unencrypted OpenSSH ECDSA-384 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa384_unencrypted"))
        assertEquals("ecdsa-sha2-nistp384", key.keyType)
    }

    @Test
    fun `reads unencrypted OpenSSH ECDSA-521 key`() {
        val key = PrivateKeyReader.read(readKey("ecdsa521_unencrypted"))
        assertEquals("ecdsa-sha2-nistp521", key.keyType)
    }

    // OpenSSH format - RSA

    @Test
    fun `reads unencrypted OpenSSH RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_unencrypted"))
        assertEquals("ssh-rsa", key.keyType)
        assertEquals("rsa-sha2-512", key.signatureAlgorithm)
        assertNotNull(key.jcaKeyPair.private)
    }

    @Test
    fun `reads encrypted OpenSSH RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_encrypted"), "testpass")
        assertEquals("ssh-rsa", key.keyType)
        assertNotNull(key.jcaKeyPair.private)
    }

    // Traditional PEM format

    @Test
    fun `reads unencrypted PEM RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_pem_unencrypted.pem"))
        assertEquals("ssh-rsa", key.keyType)
        assertEquals("rsa-sha2-512", key.signatureAlgorithm)
    }

    @Test
    fun `reads encrypted PEM RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_pem_encrypted.pem"), "testpass")
        assertEquals("ssh-rsa", key.keyType)
    }

    @Test
    fun `reads unencrypted PEM EC key`() {
        val key = PrivateKeyReader.read(readKey("ec_pem_unencrypted.pem"))
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
    }

    @Test
    fun `reads encrypted PEM EC key`() {
        val key = PrivateKeyReader.read(readKey("ec_pem_encrypted.pem"), "testpass")
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
    }

    @Test
    fun `rejects excessive integer allocation in PKCS1 RSA key`() {
        val der = byteArrayOf(
            0x30,
            0x06,
            0x02,
            0x84.toByte(),
            0x7F,
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
        )

        assertFailsWith<SshException> {
            PrivateKeyReader.read(pem("RSA PRIVATE KEY", der))
        }
    }

    @Test
    fun `rejects excessive octet string allocation in SEC1 EC key`() {
        val der = byteArrayOf(
            0x30,
            0x09,
            0x02,
            0x01,
            0x01,
            0x04,
            0x84.toByte(),
            0x7F,
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
        )

        assertFailsWith<SshException> {
            PrivateKeyReader.read(pem("EC PRIVATE KEY", der))
        }
    }

    // PKCS#8 format

    @Test
    fun `reads PKCS8 Ed25519 key`() {
        val key = PrivateKeyReader.read(readKey("ed25519_pkcs8.pem"))
        assertEquals("ssh-ed25519", key.keyType)
        assertEquals("ssh-ed25519", key.signatureAlgorithm)
    }

    @Test
    fun `reads PKCS8 EC key`() {
        val key = PrivateKeyReader.read(readKey("ec_pkcs8.pem"))
        assertEquals("ecdsa-sha2-nistp256", key.keyType)
    }

    @Test
    fun `reads PKCS8 RSA key`() {
        val key = PrivateKeyReader.read(readKey("rsa_pkcs8.pem"))
        assertEquals("ssh-rsa", key.keyType)
    }

    // isEncrypted detection

    @Test
    fun `detects unencrypted OpenSSH key`() {
        assertFalse(PrivateKeyReader.isEncrypted(readKey("ed25519_unencrypted")))
    }

    @Test
    fun `detects encrypted OpenSSH key`() {
        assertTrue(PrivateKeyReader.isEncrypted(readKey("ed25519_encrypted")))
    }

    @Test
    fun `detects unencrypted PEM key`() {
        assertFalse(PrivateKeyReader.isEncrypted(readKey("rsa_pem_unencrypted.pem")))
    }

    @Test
    fun `detects encrypted PEM key`() {
        assertTrue(PrivateKeyReader.isEncrypted(readKey("rsa_pem_encrypted.pem")))
    }

    @Test
    fun `detects unencrypted PKCS8 key`() {
        assertFalse(PrivateKeyReader.isEncrypted(readKey("rsa_pkcs8.pem")))
    }

    // Error cases

    @Test
    fun `rejects unknown format`() {
        assertFailsWith<SshException> {
            PrivateKeyReader.read("not a key at all")
        }
    }

    @Test
    fun `rejects wrong passphrase for OpenSSH key`() {
        assertFailsWith<SshException> {
            PrivateKeyReader.read(readKey("ed25519_encrypted"), "wrongpass")
        }
    }

    @Test
    fun `PEM reader rejects missing markers and empty key data`() {
        for ((text, message) in listOf(
            "not a key" to "Invalid PEM: no recognized BEGIN marker found",
            "-----BEGIN RSA PRIVATE KEY-----" to "Invalid PEM: no data",
            pem("RSA PRIVATE KEY", byteArrayOf()) to "Invalid PEM: no data",
        )) {
            assertEquals(message, assertFailsWith<SshException> { PemKeyReader.read(text, null) }.message)
        }
    }

    @Test
    fun `legacy PEM encryption requires a password and complete cipher metadata`() {
        val body = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
        val tail = "\nAQ==\n-----END RSA PRIVATE KEY-----"
        assertEquals(
            "PEM is encrypted, but no passphrase was specified",
            assertFailsWith<SshException> { PemKeyReader.read(body + tail, null) }.message,
        )
        assertEquals(
            "Broken PEM: no DEK-Info but encryption enabled",
            assertFailsWith<SshException> { PemKeyReader.read(body + tail, "password") }.message,
        )
        assertEquals(
            "Broken PEM: DEK-Info is incomplete",
            assertFailsWith<SshException> { PemKeyReader.read(body + "DEK-Info: AES-128-CBC\n" + tail, "password") }.message,
        )
    }

    @Test
    fun `non-encryption PEM headers preserve an unencrypted key`() {
        val original = readKey("rsa_pem_unencrypted.pem")
        val expected = PemKeyReader.read(original, null)
        for (procType in listOf("4", "4,PLAIN", "4,ENCRYPTED,extra")) {
            val text = "preamble\n" + original.replace(
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----\nComment: retained key\nProc-Type: $procType",
            )
            assertFalse(PemKeyReader.isEncrypted(text))
            val actual = PemKeyReader.read(text, null)
            assertContentEquals(expected.jcaKeyPair.public.encoded, actual.jcaKeyPair.public.encoded)
            assertContentEquals(expected.jcaKeyPair.private.encoded, actual.jcaKeyPair.private.encoded)
        }
    }

    @Test
    fun `legacy keys reject unsupported structure versions`() {
        val rsa = encodeDer { sequence { integer(BigInteger.TWO) } }
        val ec = encodeDer { sequence { integer(BigInteger.ZERO) } }
        assertEquals(
            "Wrong version (2) in RSA PRIVATE KEY",
            assertFailsWith<SshException> { PemKeyReader.readPkcs1Rsa(rsa) }.message,
        )
        assertEquals(
            "Wrong version (0) in EC PRIVATE KEY",
            assertFailsWith<SshException> { PemKeyReader.readSec1Ec(ec) }.message,
        )
    }

    @Test
    fun `SEC1 keys require curve and public point metadata`() {
        val noCurve = encodeDer {
            sequence {
                integer(BigInteger.ONE)
                octetString(byteArrayOf(1))
                contextTag(2) { nullValue() }
            }
        }
        val noPublic = encodeDer {
            sequence {
                integer(BigInteger.ONE)
                octetString(byteArrayOf(1))
                contextTag(0) { objectIdentifier(PemKeyReader.SECP256R1_OID) }
            }
        }
        assertEquals("EC key missing curve OID", assertFailsWith<SshException> { PemKeyReader.readSec1Ec(noCurve) }.message)
        assertEquals("EC key missing public key", assertFailsWith<SshException> { PemKeyReader.readSec1Ec(noPublic) }.message)
        assertEquals("Unknown EC curve OID", assertFailsWith<SshException> { PemKeyReader.oidToCurve(byteArrayOf(42, 3)) }.message)
    }

    @Test
    fun `PKCS8 reader rejects unsupported algorithm and unterminated companion key`() {
        val unsupported = encodeDer {
            sequence {
                integer(BigInteger.ZERO)
                sequence { objectIdentifier(byteArrayOf(42, 3)) }
                octetString(byteArrayOf(1))
            }
        }
        assertEquals(
            "Unable to parse PKCS#8 key: unsupported algorithm",
            assertFailsWith<SshException> { PemKeyReader.read(pem("PRIVATE KEY", unsupported), null) }.message,
        )
        val text = readKey("ed25519_pkcs8.pem") + "\n-----BEGIN PUBLIC KEY-----\nAQ=="
        assertEquals("Unterminated PUBLIC KEY PEM block", assertFailsWith<SshException> { PemKeyReader.read(text, null) }.message)
    }

    private fun pem(type: String, der: ByteArray): String = buildString {
        appendLine("-----BEGIN $type-----")
        appendLine(Base64Compat.encodeWithPadding(der))
        appendLine("-----END $type-----")
    }
}
