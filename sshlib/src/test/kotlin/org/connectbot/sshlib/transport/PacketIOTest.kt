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

package org.connectbot.sshlib.transport

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.crypto.AeadResult
import org.connectbot.sshlib.crypto.AesCbcCipher
import org.connectbot.sshlib.crypto.AesCtrCipher
import org.connectbot.sshlib.crypto.AesGcmCipher
import org.connectbot.sshlib.crypto.ChaCha20Poly1305Cipher
import org.connectbot.sshlib.crypto.HmacSha256
import org.connectbot.sshlib.crypto.PacketAead
import org.connectbot.sshlib.protocol.SshEnums
import org.connectbot.sshlib.protocol.SshMsgChannelData
import org.connectbot.sshlib.protocol.SshMsgKexinit
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.createNameList
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.test.assertFailsWith

class PacketIOTest {

    @Test
    fun `typed AEAD channel decoding authenticates and rejects truncated inner strings`() = runBlocking {
        val data = ByteArray(32768) { it.toByte() }
        val body = SshMsgChannelData().apply {
            setRecipientChannel(7)
            setData(createByteString(data))
            _check()
        }.toByteArray()
        suspend fun encode(payload: ByteArray): ByteArray {
            val transport = ByteArrayTransport()
            val writer = PacketIO(transport)
            writer.enableSendAead(AesGcmCipher(ByteArray(16), ByteArray(12)))
            writer.writePacket(94, payload)
            return transport.getWrittenData()
        }
        suspend fun decode(wire: ByteArray): org.connectbot.sshlib.protocol.UnencryptedPacket.UnencryptedPayload {
            val input = ByteArrayTransport(wire)
            val reads = mutableListOf<Pair<ByteArray, ByteArray>>()
            val tracking = object : Transport by input {
                override suspend fun read(count: Int): ByteArray = input.read(count).also { reads += it to it.copyOf() }
            }
            val transport = tracking
            val reader = PacketIO(transport, decodeChannelData = true)
            reader.enableReceiveAead(AesGcmCipher(ByteArray(16), ByteArray(12)))
            val packet = reader.readPacket()
            reads.forEach { (actual, original) -> assertArrayEquals(original, actual) }
            return packet
        }
        val wire = encode(body)
        run {
            val parsed = decode(wire)
            assertEquals(7L, parsed.channelData().recipientChannel())
            assertArrayEquals(data, parsed.channelData().data().data())
            val altered = wire.copyOf()
            altered[altered.lastIndex] = (altered.last().toInt() xor 1).toByte()
            assertTrue(assertFailsWith<TransportException> { decode(altered) }.message.orEmpty().contains("authentication"))
            assertTrue(assertFailsWith<TransportException> { decode(encode(body.copyOf(body.size - 1))) }.message.orEmpty().contains("Malformed SSH packet payload"))
        }
    }

    @Test
    fun `batch protection advances each sequence and preserves the following packet`() = runBlocking {
        for (mode in listOf("plain", "gcm", "chacha", "mac", "etm")) {
            fun protect(io: PacketIO) {
                when (mode) {
                    "gcm" -> io.enableAead(AesGcmCipher(ByteArray(16), ByteArray(12)), AesGcmCipher(ByteArray(16), ByteArray(12)))

                    "chacha" -> io.enableAead(ChaCha20Poly1305Cipher(ByteArray(64)), ChaCha20Poly1305Cipher(ByteArray(64)))

                    "mac", "etm" -> io.enableEncryption(
                        AesCtrCipher(ByteArray(16), ByteArray(16), forEncryption = true),
                        HmacSha256(ByteArray(32)),
                        AesCtrCipher(ByteArray(16), ByteArray(16), forEncryption = false),
                        HmacSha256(ByteArray(32)),
                        clientToServerEtm = mode == "etm",
                        serverToClientEtm = mode == "etm",
                    )
                }
            }
            val payloads = (0..3).map { value ->
                SshMsgChannelData().apply {
                    setRecipientChannel(7)
                    setData(createByteString(byteArrayOf(value.toByte())))
                    _check()
                }.toByteArray()
            }
            val transport = ByteArrayTransport()
            val writer = PacketIO(transport)
            protect(writer)
            writer.writePackets(payloads.take(3).map { 94 to it })
            writer.writePacket(94, payloads.last())
            val reader = PacketIO(ByteArrayTransport(transport.getWrittenData()), decodeChannelData = true)
            protect(reader)
            for (value in 0..3) {
                val received = reader.readPacketWithSequence()
                assertEquals(value.toLong(), received.sequenceNumber, mode)
                assertArrayEquals(byteArrayOf(value.toByte()), received.payload.channelData().data().data(), mode)
            }
        }
    }

    private class TrackingSecureRandom : SecureRandom() {
        var requestedBytes = 0

        override fun nextBytes(bytes: ByteArray) {
            requestedBytes += bytes.size
            bytes.fill(0x5a)
        }
    }

    private class TrackingAead : PacketAead {
        var destroyed = false

        override val tagLength: Int = 16

        override fun encrypt(packetLength: ByteArray, plaintext: ByteArray): AeadResult = AeadResult(plaintext.copyOf(), ByteArray(tagLength))

        override fun decrypt(packetLength: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray = ciphertext.copyOf()

        override fun destroy() {
            destroyed = true
        }

        override fun isDestroyed(): Boolean = destroyed
    }

    @Test
    fun `unencrypted round trip works`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)

        val messageType = SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt()
        // SSH_MSG_IGNORE payload is a byte_string (uint32 length + data)
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()

        io.writePacket(messageType, payload)

        val writtenData = transport.getWrittenData()
        val readTransport = ByteArrayTransport(writtenData)
        val readIO = PacketIO(readTransport)

        val parsed = readIO.readPacket()
        assertEquals(SshEnums.MessageType.SSH_MSG_IGNORE, parsed.messageType())
    }

    @Test
    fun `readBanner handles valid banner`() = runBlocking {
        val bannerLine = "2.0-TestServer_1.0"
        val banner = "SSH-$bannerLine\r\n"
        val transport = ByteArrayTransport(banner.toByteArray())
        val io = PacketIO(transport)

        val parsedBanner = io.readBanner()
        // IdBanner._read uses readBytesTerm(10, false, true, true)
        // This includes \r if present before \n
        assertEquals(bannerLine + "\r", parsedBanner.protoVersion())
    }

    @ParameterizedTest
    @ValueSource(strings = ["\n", "\r\n", "\r\r\n"])
    fun `legacy banner preserves the following KEXINIT packet`(ending: String) = runBlocking {
        val kex = SshMsgKexinit().apply {
            setCookie(ByteArray(16))
            setKexAlgorithms(createNameList("diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"))
            setServerHostKeyAlgorithms(createNameList("ssh-rsa"))
            setEncryptionAlgorithmsClientToServer(createNameList("aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"))
            setEncryptionAlgorithmsServerToClient(createNameList("aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"))
            setMacAlgorithmsClientToServer(createNameList("hmac-sha1,hmac-sha1-96,hmac-md5"))
            setMacAlgorithmsServerToClient(createNameList("hmac-sha1,hmac-sha1-96,hmac-md5"))
            setCompressionAlgorithmsClientToServer(createNameList("none"))
            setCompressionAlgorithmsServerToClient(createNameList("none"))
            setLanguagesClientToServer(createNameList(""))
            setLanguagesServerToClient(createNameList(""))
            setFirstKexPacketFollows(0)
            setReserved(0)
            _check()
        }
        val encoded = ByteArrayTransport()
        PacketIO(encoded, TrackingSecureRandom()).writePacket(20, kex.toByteArray())
        val packet = encoded.getWrittenData()
        assertTrue(packet.size > 255)
        val banner = "SSH-2.0-OpenSSH_3.7.1p2$ending"
        val transport = ByteArrayTransport(banner.toByteArray(Charsets.US_ASCII) + packet)
        val io = PacketIO(transport)

        assertEquals("2.0-OpenSSH_3.7.1p2" + ending.removeSuffix("\n"), io.readBanner().protoVersion())
        assertEquals(packet.size, transport.bytesRemaining)
        val received = io.readPacket()
        assertEquals(SshEnums.MessageType.SSH_MSG_KEXINIT, received.messageType())
        assertArrayEquals(kex.toByteArray(), (received.body() as SshMsgKexinit).toByteArray())
        assertTrue(transport.isInputExhausted)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "2.0-OpenSSH_3.7.1p2",
            "2.0-OpenSSH_5.0",
            "1.99-OpenSSH_5.3",
            "2.0-OpenSSH_7.4",
            "2.0-OpenSSH_10.6",
            "2.0-dropbear_2026.91",
            "2.0-UnknownServer",
            "2.0-FutureServer_99.0 vendor comment",
        ],
    )
    fun `LF and CRLF banners preserve the next packet regardless of server version`(version: String) = runBlocking {
        val following = byteArrayOf(0, 0, 1, 0)
        for (ending in listOf("\n", "\r\n", "\r\r\n")) {
            val transport = ByteArrayTransport("SSH-$version$ending".toByteArray(Charsets.US_ASCII) + following)
            assertEquals(version + ending.removeSuffix("\n"), PacketIO(transport).readBanner().protoVersion())
            assertArrayEquals(following, transport.read(following.size))
            assertTrue(transport.isInputExhausted)
        }
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "SSH-2.0-Test\u0000\n",
            "SSH-2.0-Test\u0000\r\n",
            "SSH-2.0-Test\rX\n",
            "SSH-2.0-Test\r\rX\r\n",
            "SSH-2.0-Test\r\u0000\n",
        ],
    )
    fun `readBanner rejects NUL and ordinary characters after CR`(wire: String) = runBlocking {
        val error = assertFailsWith<TransportException> { PacketIO(ByteArrayTransport(wire.toByteArray())).readBanner() }
        assertEquals("Malformed SSH identification", error.message)
    }

    @ParameterizedTest
    @ValueSource(strings = ["\n", "\r\n"])
    fun `banner length limit includes its terminator`(ending: String) = runBlocking {
        val prefix = "SSH-2.0-OpenSSH_3.7.1p2 "
        val maximum = prefix + "x".repeat(255 - prefix.length - ending.length) + ending
        assertEquals(maximum.substring(4).removeSuffix("\n"), PacketIO(ByteArrayTransport(maximum.toByteArray())).readBanner().protoVersion())
        val tooLong = maximum.dropLast(ending.length) + "x" + ending
        val error = assertFailsWith<TransportException> { PacketIO(ByteArrayTransport(tooLong.toByteArray())).readBanner() }
        assertEquals("Banner too long", error.message)
    }

    @ParameterizedTest
    @ValueSource(strings = ["SSH-2.0-OpenSSH_3.7.1p2", "SSH-2.0-OpenSSH_3.7.1p2\r", "", "\n", "BAD-2.0-Test\r\n"])
    fun `readBanner rejects truncated or malformed input`(wire: String) = runBlocking {
        val error = assertFailsWith<TransportException> { PacketIO(ByteArrayTransport(wire.toByteArray())).readBanner() }
        assertTrue(error.message.orEmpty().isNotEmpty())
    }

    @Test
    fun `writeBanner keeps the standard CRLF ending`() = runBlocking {
        val transport = ByteArrayTransport()
        PacketIO(transport).writeBanner("SSH-2.0-TestClient")
        assertArrayEquals("SSH-2.0-TestClient\r\n".toByteArray(Charsets.US_ASCII), transport.getWrittenData())
    }

    @Test
    fun `readBanner throws on too long banner`() {
        val longBanner = "A".repeat(300) + "\r\n"
        val transport = ByteArrayTransport(longBanner.toByteArray())
        val io = PacketIO(transport)

        assertThrows(TransportException::class.java) {
            runBlocking {
                io.readBanner()
            }
        }
    }

    @Test
    fun `readPacket throws on invalid packet length`() {
        // Packet length too small (MIN_PACKET_LENGTH is 6)
        val invalidLength = byteArrayOf(0, 0, 0, 1)
        val transport = ByteArrayTransport(invalidLength)
        val io = PacketIO(transport)

        assertThrows(TransportException::class.java) {
            runBlocking {
                io.readPacket()
            }
        }
    }

    @Test
    fun `readPacket throws on too large packet length`() {
        // Packet length too large (MAX_PACKET_LENGTH is 35000)
        val length = 40000
        val invalidLength = byteArrayOf(
            ((length shr 24) and 0xFF).toByte(),
            ((length shr 16) and 0xFF).toByte(),
            ((length shr 8) and 0xFF).toByte(),
            (length and 0xFF).toByte(),
        )
        val transport = ByteArrayTransport(invalidLength)
        val io = PacketIO(transport)

        assertThrows(TransportException::class.java) {
            runBlocking {
                io.readPacket()
            }
        }
    }

    @Test
    fun `readPacket wraps Kaitai validation failure as TransportException`() {
        val malformedIgnore = byteArrayOf(
            0, 0, 0, 14,
            4,
            SshEnums.MessageType.SSH_MSG_IGNORE.id().toByte(),
            0x40, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        )
        val io = PacketIO(ByteArrayTransport(malformedIgnore))

        val error = assertThrows(TransportException::class.java) {
            runBlocking { io.readPacket() }
        }

        assertEquals("Malformed SSH packet payload", error.message)
        assertTrue(error.cause is io.kaitai.struct.KaitaiStream.ValidationExprError)
    }

    @Test
    fun `reset sequence numbers works`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)

        io.resetSendSequenceNumber()
        io.resetReceiveSequenceNumber()
    }

    @Test
    fun `outbound and inbound AEAD keys are replaced independently`() {
        val io = PacketIO(ByteArrayTransport())
        val oldOutbound = TrackingAead()
        val oldInbound = TrackingAead()
        val newOutbound = TrackingAead()
        val newInbound = TrackingAead()
        io.enableAead(oldOutbound, oldInbound)

        io.enableSendAead(newOutbound)

        assertTrue(oldOutbound.destroyed)
        assertFalse(oldInbound.destroyed)

        io.enableReceiveAead(newInbound)

        assertTrue(oldInbound.destroyed)
        assertFalse(newOutbound.destroyed)
        assertFalse(newInbound.destroyed)
    }

    @Test
    fun `bytesSentOnWire tracks unencrypted write`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)

        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()
        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), payload)
        assertTrue(io.bytesSentOnWire > 0)
        assertEquals(io.bytesSentOnWire, transport.getWrittenData().size.toLong())
    }

    @Test
    fun `bytesReceivedOnWire tracks unencrypted read`() = runBlocking {
        val transport = ByteArrayTransport()
        val writer = PacketIO(transport)
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()
        writer.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), payload)

        val readTransport = ByteArrayTransport(transport.getWrittenData())
        val reader = PacketIO(readTransport)
        reader.readPacket()

        assertEquals(transport.getWrittenData().size.toLong(), reader.bytesReceivedOnWire)
    }

    @Test
    fun `resetByteCounters zeroes both counters`() = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val payload = ByteBuffer.allocate(4 + data.size)
            .putInt(data.size)
            .put(data)
            .array()
        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), payload)
        assertTrue(io.bytesSentOnWire > 0)

        io.resetByteCounters()
        assertEquals(0L, io.bytesSentOnWire)
        assertEquals(0L, io.bytesReceivedOnWire)
    }

    @Test
    fun `encrypt-and-MAC rejects tampered MAC`() {
        val cipherKey = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it + 0x10).toByte() }
        val macKey = ByteArray(32) { (it + 0x20).toByte() }

        val writeTransport = ByteArrayTransport()
        val writeIO = PacketIO(writeTransport)
        writeIO.enableEncryption(
            clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
        )
        runBlocking { writeIO.writePacket(SshEnums.MessageType.SSH_MSG_NEWKEYS.id().toInt()) }

        val wireData = writeTransport.getWrittenData().clone()
        wireData[wireData.size - 1] = (wireData[wireData.size - 1].toInt() xor 0xFF).toByte()

        val readTransport = ByteArrayTransport(wireData)
        val readIO = PacketIO(readTransport)
        readIO.enableEncryption(
            clientToServerCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = true),
            clientToServerMac = HmacSha256(macKey.copyOf()),
            serverToClientCipher = AesCbcCipher(cipherKey, iv.copyOf(), forEncryption = false),
            serverToClientMac = HmacSha256(macKey.copyOf()),
        )

        assertThrows(TransportException::class.java) {
            runBlocking { readIO.readPacket() }
        }
    }

    // calculatePaddingLength: totalLength = 4 + 1 + (1 + payload.size) = 6 + payload.size.
    // With blockSize=8: raw = if (totalLength%8==0) 8 else 8-(totalLength%8). Bump by 8 if raw<4.
    // Verifying the exact padding_length byte at wire[4] kills MathMutator and ConditionalsBoundaryMutator survivors.

    private fun writtenPaddingLength(payloadSize: Int): Int = runBlocking {
        val transport = ByteArrayTransport()
        val io = PacketIO(transport)
        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt(), ByteArray(payloadSize))
        transport.getWrittenData()[4].toInt() and 0xFF
    }

    @Test
    fun `calculatePaddingLength produces minimum 4 bytes of padding`() {
        for (payloadSize in 0..64) {
            val padding = writtenPaddingLength(payloadSize)
            assertTrue(padding >= 4, "payload=$payloadSize: padding $padding < 4")
        }
    }

    @Test
    fun `packet padding comes from cryptographically secure random source`() = runBlocking {
        val transport = ByteArrayTransport()
        val random = TrackingSecureRandom()
        val io = PacketIO(transport, random)

        io.writePacket(SshEnums.MessageType.SSH_MSG_IGNORE.id().toInt())

        val wire = transport.getWrittenData()
        val paddingLength = wire[4].toInt() and 0xFF
        assertEquals(paddingLength, random.requestedBytes)
        assertTrue(wire.takeLast(paddingLength).all { it == 0x5a.toByte() })
    }

    @Test
    fun `calculatePaddingLength result aligns total wire packet to multiple of 8`() {
        // totalLength in RFC 4253 = 4(length field) + 1(padding_length) + 1(msg_type) + payloadSize + padding
        // = 6 + payloadSize + padding must be multiple of 8
        for (payloadSize in 0..64) {
            val padding = writtenPaddingLength(payloadSize)
            val wireTotal = 6 + payloadSize + padding
            assertEquals(0, wireTotal % 8, "payload=$payloadSize: wireTotal $wireTotal not multiple of 8")
        }
    }

    @Test
    fun `calculatePaddingLength payload 2 aligns without bump`() {
        // totalLength=8 (2+6), 8%8=0, raw=8, ≥4 → no bump → padding=8
        assertEquals(8, writtenPaddingLength(2))
    }

    @Test
    fun `calculatePaddingLength payload 3 gives 7`() {
        // totalLength=9, 9%8=1, raw=7, ≥4 → padding=7
        assertEquals(7, writtenPaddingLength(3))
    }

    @Test
    fun `calculatePaddingLength payload 6 gives exactly 4 without bump`() {
        // totalLength=12, 12%8=4, raw=4, not <4 → padding=4 (boundary: mutant with <=4 would bump to 12)
        assertEquals(4, writtenPaddingLength(6))
    }

    @Test
    fun `calculatePaddingLength payload 7 gets bumped because raw is 3`() {
        // totalLength=13, 13%8=5, raw=3, <4 → bump: 3+8=11
        assertEquals(11, writtenPaddingLength(7))
    }

    @Test
    fun `calculatePaddingLength payload 0 gets bumped because raw is 2`() {
        // totalLength=6, 6%8=6, raw=2, <4 → bump: 2+8=10
        assertEquals(10, writtenPaddingLength(0))
    }
}
