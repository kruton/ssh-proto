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

package org.connectbot.sshlib

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.nio.ByteBuffer
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SshKeyRevocationListTest {
    @TempDir
    lateinit var directory: Path

    @ParameterizedTest
    @ValueSource(strings = ["serial-list", "serial-range", "serial-bitmap", "key-id", "key", "sha1", "sha256", "ca-key"])
    fun `OpenSSH generated KRL fixtures reject revoked certificates`(kind: String) = runTest {
        val krl = SshKeyRevocationList.decode(certificateResource("$kind.krl"))
        val key = certificatePublicKey()
        assertTrue(krl.isRevoked(key))
        assertFalse(CertificateAuthorityVerifier("localhost", listOf(certificateAuthority()), krl).verify(key))
        val file = directory.resolve("known_hosts").toFile().apply {
            writeText("@cert-authority localhost " + certificateResource("ca-ed25519.pub").toString(Charsets.UTF_8))
        }
        assertFalse(KnownHostsVerifier(file, "localhost", 22, krl).verify(key))
        // CA scoping prevents serial/key-ID revocations from affecting another CA.
        if (kind in listOf("serial-list", "serial-range", "serial-bitmap", "key-id", "ca-key")) {
            assertFalse(krl.isRevoked(certificatePublicKey("host-ed25519-ca-rsa")))
        }
    }

    @Test
    fun `KRL serial comparisons are unsigned and bitmap gaps do not revoke adjacent certificates`() {
        assertTrue(SshKeyRevocationList.decode(certificateResource("serial-list.krl")).isRevoked(certificatePublicKey("user-high-serial")))
        assertFalse(SshKeyRevocationList.decode(certificateResource("serial-bitmap.krl")).isRevoked(certificatePublicKey("host-rsa")))
        assertFalse(SshKeyRevocationList.decode(certificateResource("serial-range.krl")).isRevoked(certificatePublicKey("user-ed25519")))
        assertTrue(SshKeyRevocationList.decode(certificateResource("key.krl")).isRevoked(certificateFixture().publicKey))
    }

    @Test
    fun `unsigned ranges bitmaps and all CA sections match OpenSSH semantics`() {
        assertEquals(ULong.MAX_VALUE, certificateFixture("user-max-serial").serial)
        for (name in listOf("serial-high-range", "serial-high-bitmap")) {
            val krl = SshKeyRevocationList.decode(certificateResource("$name.krl"))
            assertTrue(krl.isRevoked(certificatePublicKey("user-high-serial")))
            assertFalse(krl.isRevoked(certificatePublicKey("host-ed25519")))
        }
        assertTrue(SshKeyRevocationList.decode(certificateResource("serial-high-range.krl")).isRevoked(certificatePublicKey("user-max-serial")))
        val all = SshKeyRevocationList.decode(certificateResource("all-ca-serial.krl"))
        assertTrue(all.isRevoked(certificatePublicKey("host-ed25519")))
        assertTrue(all.isRevoked(certificatePublicKey("host-ed25519-ca-rsa")))
        assertFalse(all.isRevoked(certificatePublicKey("host-rsa")))
    }

    @Test
    fun `KRL malformed nested serial sections fail closed`() {
        fun string(bytes: ByteArray) = ByteBuffer.allocate(4 + bytes.size).putInt(bytes.size).put(bytes).array()
        val header = ByteBuffer.allocate(44).put("SSHKRL\n\u0000".toByteArray()).putInt(1)
            .putLong(0).putLong(0).putLong(0).putInt(0).putInt(0).array()
        fun section(kind: Int, contents: ByteArray): ByteArray {
            val body = string(byteArrayOf()) + string(byteArrayOf()) + byteArrayOf(kind.toByte()) + string(contents)
            return header + byteArrayOf(1) + string(body)
        }
        val reversed = ByteBuffer.allocate(16).putLong(20).putLong(10).array()
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x21, reversed)) }
        val trailing = ByteBuffer.allocate(17).putLong(10).putLong(20).put(0).array()
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x21, trailing)) }
        val negativeBitmap = ByteBuffer.allocate(8).putLong(1).array() + string(byteArrayOf(255.toByte()))
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x22, negativeBitmap)) }
        val overflowingBitmap = ByteBuffer.allocate(8).putLong(-1).array() + string(byteArrayOf(2))
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x22, overflowingBitmap)) }
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x20, byteArrayOf())) }
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x20, ByteArray(8))) }
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x21, ByteBuffer.allocate(16).putLong(0).putLong(10).array())) }
        assertFailsWith<SshException> { SshKeyRevocationList.decode(section(0x22, ByteArray(8) + string(byteArrayOf(1)))) }
    }

    @Test
    fun `invalid versions flags lengths signatures and critical extensions fail closed`() {
        val valid = certificateResource("serial-range.krl")
        for (length in listOf(0, 7, 12, 25, valid.size - 1)) {
            assertFailsWith<SshException> { SshKeyRevocationList.decode(valid.copyOf(length)) }
        }
        assertFailsWith<SshException> { SshKeyRevocationList.decode(valid.copyOf().apply { this[11] = 2 }) }
        assertFailsWith<SshException> { SshKeyRevocationList.decode(valid.copyOf().apply { this[35] = 1 }) }
        // A minimal KRL with an unsupported section (including legacy signature type 4).
        val empty = ByteBuffer.allocate(44).put("SSHKRL\n\u0000".toByteArray()).putInt(1)
            .putLong(0).putLong(0).putLong(0).putInt(0).putInt(0).array()
        for (kind in listOf(4, 100)) {
            assertFailsWith<SshException> { SshKeyRevocationList.decode(empty + byteArrayOf(kind.toByte(), 0, 0, 0, 0)) }
        }
        val extension = ByteBuffer.allocate(10).putInt(1).put('x'.code.toByte()).put(1).putInt(0).array()
        val section = byteArrayOf(255.toByte()) + ByteBuffer.allocate(4).putInt(extension.size).array() + extension
        assertFailsWith<SshException> { SshKeyRevocationList.decode(empty + section) }
        val optional = section.copyOf().apply { this[10] = 0 }
        assertFalse(SshKeyRevocationList.decode(empty + optional).isRevoked(certificatePublicKey()))
    }
}
