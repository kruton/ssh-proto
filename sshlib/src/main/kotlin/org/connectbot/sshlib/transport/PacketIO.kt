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

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStream
import org.connectbot.sshlib.crypto.PacketAead
import org.connectbot.sshlib.crypto.PacketCipher
import org.connectbot.sshlib.crypto.PacketCompressor
import org.connectbot.sshlib.crypto.PacketMac
import org.connectbot.sshlib.kaitaiParseFailureOrNull
import org.connectbot.sshlib.protocol.IdBanner
import org.connectbot.sshlib.protocol.SshPacketHeader
import org.connectbot.sshlib.protocol.UnencryptedPacket
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Handles SSH packet framing and unframing according to RFC 4253.
 *
 * SSH packets have the following structure:
 * ```
 * uint32    packet_length  // excludes MAC and itself
 * byte      padding_length
 * byte[n1]  payload        // n1 = packet_length - padding_length - 1
 * byte[n2]  padding        // n2 = padding_length
 * byte[m]   mac            // m = mac_length
 * ```
 *
 * @param transport Underlying transport layer
 */
internal class PacketIO(
    private val transport: Transport,
    private val secureRandom: SecureRandom = SecureRandom(),
    private val decodeChannelData: Boolean = false,
) {
    internal data class ReceivedPacket(
        val payload: UnencryptedPacket.UnencryptedPayload,
        val sequenceNumber: Long,
        val messageNumber: Int,
    )
    companion object {
        private val logger = LoggerFactory.getLogger(PacketIO::class.java)

        // Minimum packet_length: padding_length(1) + message_type(1) + min_padding(4) = 6
        private const val MIN_PACKET_LENGTH = 6
        private const val MAX_PACKET_LENGTH = 35000
    }

    // Separate ciphers and MACs for each direction
    private var sendCipher: PacketCipher? = null
    private var sendMac: PacketMac? = null
    private var receiveCipher: PacketCipher? = null
    private var receiveMac: PacketMac? = null

    // AEAD ciphers for each direction
    private var sendAead: PacketAead? = null
    private var receiveAead: PacketAead? = null

    // Whether to use ETM (Encrypt-then-MAC) mode for each direction
    private var sendEtm: Boolean = false
    private var receiveEtm: Boolean = false

    // Separate sequence numbers for each direction (client->server and server->client)
    private var sendSequenceNumber: Long = 0
    private var receiveSequenceNumber: Long = 0

    // Compression state
    private var sendCompressor: PacketCompressor? = null
    private var receiveCompressor: PacketCompressor? = null
    private var sendCompressionActive: Boolean = false
    private var receiveCompressionActive: Boolean = false

    // Wire-byte counters for re-key threshold tracking
    @Volatile internal var bytesSentOnWire: Long = 0L

    @Volatile internal var bytesReceivedOnWire: Long = 0L

    /**
     * Enable encryption and MAC for subsequent packets.
     *
     * @param clientToServerCipher Cipher for outgoing packets
     * @param clientToServerMac MAC for outgoing packets
     * @param serverToClientCipher Cipher for incoming packets
     * @param serverToClientMac MAC for incoming packets
     * @param clientToServerEtm Whether to use ETM for outgoing packets
     * @param serverToClientEtm Whether to use ETM for incoming packets
     */
    fun enableEncryption(
        clientToServerCipher: PacketCipher,
        clientToServerMac: PacketMac,
        serverToClientCipher: PacketCipher,
        serverToClientMac: PacketMac,
        clientToServerEtm: Boolean = false,
        serverToClientEtm: Boolean = false,
    ) {
        enableSendEncryption(clientToServerCipher, clientToServerMac, clientToServerEtm)
        enableReceiveEncryption(serverToClientCipher, serverToClientMac, serverToClientEtm)
    }

    /** Install cipher and MAC protection for subsequent outbound packets. */
    fun enableSendEncryption(cipher: PacketCipher, mac: PacketMac, etm: Boolean = false) {
        sendAead?.destroy()
        sendAead = null
        sendCipher?.destroy()
        sendMac?.destroy()
        sendCipher = cipher
        sendMac = mac
        sendEtm = etm
    }

    /** Install cipher and MAC protection for subsequent inbound packets. */
    fun enableReceiveEncryption(cipher: PacketCipher, mac: PacketMac, etm: Boolean = false) {
        receiveAead?.destroy()
        receiveAead = null
        receiveCipher?.destroy()
        receiveMac?.destroy()
        receiveCipher = cipher
        receiveMac = mac
        receiveEtm = etm
    }

    /**
     * Enable AEAD encryption for subsequent packets.
     *
     * @param clientToServerAead AEAD cipher for outgoing packets
     * @param serverToClientAead AEAD cipher for incoming packets
     */
    fun enableAead(
        clientToServerAead: PacketAead,
        serverToClientAead: PacketAead,
    ) {
        enableSendAead(clientToServerAead)
        enableReceiveAead(serverToClientAead)
    }

    /** Install AEAD protection for subsequent outbound packets. */
    fun enableSendAead(aead: PacketAead) {
        sendCipher?.destroy()
        sendCipher = null
        sendMac?.destroy()
        sendMac = null
        sendEtm = false
        sendAead?.destroy()
        sendAead = aead
    }

    /** Install AEAD protection for subsequent inbound packets. */
    fun enableReceiveAead(aead: PacketAead) {
        receiveCipher?.destroy()
        receiveCipher = null
        receiveMac?.destroy()
        receiveMac = null
        receiveEtm = false
        receiveAead?.destroy()
        receiveAead = aead
    }

    /**
     * Reset send sequence numbers to 0.
     * Required by strict KEX after NEWKEYS exchange (draft-ietf-sshm-strict-kex-01).
     */
    fun resetSendSequenceNumber() {
        sendSequenceNumber = 0
    }

    /**
     * Reset receive sequence number to 0.
     * Required by strict KEX after NEWKEYS exchange (draft-ietf-sshm-strict-kex-01).
     */
    fun resetReceiveSequenceNumber() {
        receiveSequenceNumber = 0
    }

    /**
     * Install compressors for both directions.
     *
     * @param clientToServer Compressor for outgoing packets (null for "none")
     * @param serverToClient Compressor for incoming packets (null for "none")
     * @param immediateActivation If true, compression starts immediately; if false,
     *   compressors are installed but inactive until [activateCompression] is called.
     */
    fun enableCompression(
        clientToServer: PacketCompressor?,
        serverToClient: PacketCompressor?,
        immediateActivation: Boolean,
    ) {
        enableSendCompression(clientToServer, immediateActivation)
        enableReceiveCompression(serverToClient, immediateActivation)
    }

    /** Install the compressor used for subsequent outbound packets. */
    fun enableSendCompression(compressor: PacketCompressor?, immediateActivation: Boolean) {
        sendCompressor = compressor
        sendCompressionActive = immediateActivation && compressor != null
    }

    /** Install the compressor used for subsequent inbound packets. */
    fun enableReceiveCompression(compressor: PacketCompressor?, immediateActivation: Boolean) {
        receiveCompressor = compressor
        receiveCompressionActive = immediateActivation && compressor != null
    }

    /**
     * Activate installed-but-inactive compressors.
     * Used for `zlib@openssh.com` which delays compression until after user authentication.
     */
    fun activateCompression() {
        if (sendCompressor != null) sendCompressionActive = true
        if (receiveCompressor != null) receiveCompressionActive = true
    }

    fun resetByteCounters() {
        bytesSentOnWire = 0L
        bytesReceivedOnWire = 0L
    }

    /**
     * Read and parse the next SSH packet, decompressing if compression is active.
     *
     * @return Parsed SSH message payload
     * @throws TransportException if packet is malformed or transport fails
     */
    suspend fun readPacket(): UnencryptedPacket.UnencryptedPayload = readPacketWithSequence().payload

    /** Read a packet together with the uint32 sequence number that authenticated it. */
    suspend fun readPacketWithSequence(): ReceivedPacket {
        val sequenceNumber = receiveSequenceNumber
        val rawPayload = readRawPayloadStream()

        val compressor = receiveCompressor
        val payloadStream = if (compressor != null && receiveCompressionActive) {
            ByteBufferKaitaiStream(compressor.uncompress(rawPayload.readBytesFull()))
        } else {
            rawPayload
        }
        val payload = parsePayloadStream(payloadStream)
        return ReceivedPacket(
            payload = payload,
            sequenceNumber = sequenceNumber,
            messageNumber = payload.messageNumber(),
        )
    }

    /**
     * Parse the already bounded, authenticated payload directly with Kaitai.
     * The payload schema uses its stream size and does not require a packet envelope.
     */
    private fun parsePayloadStream(stream: KaitaiStream): UnencryptedPacket.UnencryptedPayload {
        try {
            val payload = UnencryptedPacket.UnencryptedPayload(stream, decodeChannelData)
            payload._read()
            return payload
        } catch (e: RuntimeException) {
            val parseFailure = e.kaitaiParseFailureOrNull() ?: throw e
            throw TransportException("Malformed SSH packet payload", parseFailure)
        }
    }

    /**
     * Read and decrypt/verify the next SSH packet, returning a bounded payload view
     * (message_type + body) before decompression.
     */
    private suspend fun readRawPayloadStream(): KaitaiStream {
        val currentAead = receiveAead
        if (currentAead != null) {
            return readAeadPacketStream(currentAead)
        }

        val currentCipher = receiveCipher
        val currentMac = receiveMac

        if (currentCipher == null || currentMac == null) {
            return readUnencryptedPacketStream()
        } else if (receiveEtm) {
            return readEtmPacketStream(currentCipher, currentMac)
        } else {
            return readEncryptedPacketStream(currentCipher, currentMac)
        }
    }

    /** Parse a bounded decrypted body directly; no copied length-field envelope is needed. */
    private fun extractPayloadStream(body: ByteBuffer): KaitaiStream {
        try {
            val stream = ByteBufferKaitaiStream(body)
            val header = SshPacketHeader(stream)
            header._read()
            // The generated schema validates the boundary; the runtime provides a bounded view.
            return stream.substream(header.payloadLength().toLong())
        } catch (e: RuntimeException) {
            val parseFailure = e.kaitaiParseFailureOrNull() ?: throw e
            throw TransportException("Malformed SSH packet body", parseFailure)
        }
    }

    private suspend fun readUnencryptedPacketStream(): KaitaiStream {
        // Read packet_length (4 bytes)
        val lengthBytes = transport.read(4)
        bytesReceivedOnWire += 4
        val packetLength = ByteBuffer.wrap(lengthBytes).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid packet length: $packetLength")
        }

        // Read rest of packet
        val packetData = transport.read(packetLength)
        bytesReceivedOnWire += packetLength

        receiveSequenceNumber++
        return extractPayloadStream(ByteBuffer.wrap(packetData))
    }

    private suspend fun readEncryptedPacketStream(cipher: PacketCipher, mac: PacketMac): KaitaiStream {
        val blockSize = cipher.blockSize
        val macLength = mac.macLength

        // Read first block (contains packet_length)
        val firstBlock = transport.read(blockSize)
        bytesReceivedOnWire += blockSize
        val decryptedFirst = cipher.decrypt(firstBlock)

        // Extract packet_length
        val packetLength = ByteBuffer.wrap(decryptedFirst, 0, 4).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid encrypted packet length: $packetLength")
        }

        // Read remaining encrypted data
        val remainingLength = packetLength - blockSize + 4
        val remainingData = if (remainingLength.compareTo(0) > 0) {
            transport.read(remainingLength).also { bytesReceivedOnWire += remainingLength }
        } else {
            byteArrayOf()
        }

        // Read MAC
        val receivedMac = transport.read(macLength)
        bytesReceivedOnWire += macLength

        // Decrypt remaining data
        val decryptedRemaining = if (remainingData.isNotEmpty()) {
            cipher.decrypt(remainingData)
        } else {
            byteArrayOf()
        }

        // Combine decrypted blocks
        val decryptedPacket = decryptedFirst + decryptedRemaining

        // Verify MAC (over plaintext for encrypt-and-MAC)
        val expectedMac = mac.compute(receiveSequenceNumber, decryptedPacket)
        if (!MessageDigest.isEqual(receivedMac, expectedMac)) {
            logger.error("MAC verification failed for seq=$receiveSequenceNumber")
            logger.error("  Received MAC: ${receivedMac.joinToString("") { "%02x".format(it) }}")
            logger.error("  Expected MAC: ${expectedMac.joinToString("") { "%02x".format(it) }}")
            logger.error("  Decrypted packet (${decryptedPacket.size} bytes): ${decryptedPacket.joinToString("") { "%02x".format(it) }}")
            throw TransportException("MAC verification failed")
        }

        receiveSequenceNumber++
        return extractPayloadStream(ByteBuffer.wrap(decryptedPacket, 4, decryptedPacket.size - 4).slice())
    }

    /**
     * Read an ETM (Encrypt-then-MAC) packet.
     *
     * In ETM mode, the MAC is computed over (sequence_number || encrypted_length || encrypted_payload).
     * The length field is NOT encrypted.
     */
    private suspend fun readEtmPacketStream(cipher: PacketCipher, mac: PacketMac): KaitaiStream {
        val macLength = mac.macLength

        // In ETM mode, length is NOT encrypted
        val lengthBytes = transport.read(4)
        bytesReceivedOnWire += 4
        val encryptedLength = ByteBuffer.wrap(lengthBytes).int

        if (encryptedLength < MIN_PACKET_LENGTH || encryptedLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid ETM packet length: $encryptedLength")
        }

        // Read encrypted payload
        val encryptedPayload = transport.read(encryptedLength)
        bytesReceivedOnWire += encryptedLength

        // Read MAC
        val receivedMac = transport.read(macLength)
        bytesReceivedOnWire += macLength

        // Verify MAC (over sequence_number || length || encrypted_payload)
        val expectedMac = mac.computeEtm(receiveSequenceNumber, encryptedLength, encryptedPayload)
        if (!MessageDigest.isEqual(receivedMac, expectedMac)) {
            logger.error("ETM MAC verification failed for seq=$receiveSequenceNumber")
            throw TransportException("ETM MAC verification failed")
        }

        // Decrypt
        val decryptedPayload = cipher.decrypt(encryptedPayload)

        receiveSequenceNumber++
        return extractPayloadStream(ByteBuffer.wrap(decryptedPayload))
    }

    /**
     * Read an AEAD packet (e.g., AES-GCM per RFC 5647).
     *
     * Wire format: packet_length (4B, cleartext) || ciphertext || auth_tag (16B)
     * AAD: the 4-byte packet_length
     * Plaintext: padding_length || payload || padding
     *
     * For ciphers that encrypt the length (e.g., ChaCha20-Poly1305):
     * Wire format: encrypted_length (4B) || ciphertext || auth_tag (16B)
     * The encrypted length bytes are passed as AAD to encrypt/decrypt.
     */
    private suspend fun readAeadPacketStream(aead: PacketAead): KaitaiStream {
        val wireLength = transport.read(4)
        bytesReceivedOnWire += 4

        val lengthBytes: ByteArray
        val aadBytes: ByteArray
        if (aead.encryptsLength) {
            aadBytes = wireLength.clone()
            lengthBytes = aead.decryptLength(receiveSequenceNumber, wireLength)
        } else {
            lengthBytes = wireLength
            aadBytes = wireLength
        }

        val packetLength = ByteBuffer.wrap(lengthBytes).int

        if (packetLength < MIN_PACKET_LENGTH || packetLength > MAX_PACKET_LENGTH) {
            throw TransportException("Invalid AEAD packet length: $packetLength")
        }

        val encrypted = transport.read(packetLength + aead.tagLength)
        bytesReceivedOnWire += encrypted.size
        val plaintext = ByteBuffer.wrap(aead.decryptPacket(aadBytes, encrypted))

        receiveSequenceNumber++
        return extractPayloadStream(plaintext)
    }

    /**
     * Write an SSH packet, compressing if compression is active.
     *
     * @param messageType SSH message type code
     * @param payload Message payload (excluding message type byte)
     */
    suspend fun writePacket(messageType: Int, payload: ByteArray = byteArrayOf()) {
        val buffers = encodePacket(messageType, payload, sendSequenceNumber)
        writeBuffers(buffers)
        bytesSentOnWire += buffers.sumOf { it.size }
        sendSequenceNumber++
    }

    // Only PacketWriter uses this, with a bounded contiguous run of channel-data packets.
    // Protection changes and write callbacks occur outside the batch.
    suspend fun writePackets(packets: List<Pair<Int, ByteArray>>) {
        val buffers = ArrayList<ByteArray>(packets.size * 2)
        for ((index, packet) in packets.withIndex()) {
            buffers.addAll(encodePacket(packet.first, packet.second, sendSequenceNumber + index))
        }
        writeBuffers(buffers)
        bytesSentOnWire += buffers.sumOf { it.size }
        sendSequenceNumber += packets.size
    }

    /** One owned contiguous batch keeps custom transports on the existing write API. */
    private suspend fun writeBuffers(buffers: List<ByteArray>) {
        if (buffers.size == 1) {
            transport.write(buffers.single())
        } else {
            val output = ByteBuffer.allocate(buffers.sumOf { it.size })
            buffers.forEach { output.put(it) }
            transport.write(output.array())
        }
    }

    /** Compression, padding, and protection are synchronous; only the transport write suspends. */
    private fun encodePacket(messageType: Int, payload: ByteArray, sequenceNumber: Long): List<ByteArray> {
        val compressor = sendCompressor
        if (compressor != null && sendCompressionActive) {
            val compressed = compressor.compress(byteArrayOf(messageType.toByte()) + payload)
            return encodeRawPacket(compressed[0].toInt() and 0xFF, compressed.copyOfRange(1, compressed.size), sequenceNumber)
        }
        return encodeRawPacket(messageType, payload, sequenceNumber)
    }

    private fun encodeRawPacket(messageType: Int, payload: ByteArray, sequenceNumber: Long): List<ByteArray> {
        logger.debug("Writing packet type $messageType (seq=$sequenceNumber)")
        val currentAead = sendAead
        if (currentAead != null) return encodeAeadPacket(messageType, payload, currentAead, sequenceNumber)
        val currentCipher = sendCipher
        val currentMac = sendMac
        return when {
            currentCipher == null || currentMac == null -> encodeUnencryptedPacket(messageType, payload)
            sendEtm -> encodeEtmPacket(messageType, payload, currentCipher, currentMac, sequenceNumber)
            else -> encodeEncryptedPacket(messageType, payload, currentCipher, currentMac, sequenceNumber)
        }
    }

    private fun encodeUnencryptedPacket(messageType: Int, payload: ByteArray): List<ByteArray> {
        val payloadLength = 1 + payload.size // message type + payload
        val blockSize = 8 // Minimum block size per RFC 4253

        // Calculate padding
        val paddingLength = calculatePaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // Build packet
        val buffer = ByteArrayOutputStream(packetLength + 4)

        // packet_length (4 bytes)
        buffer.write(ByteBuffer.allocate(4).putInt(packetLength).array())

        // padding_length (1 byte)
        buffer.write(paddingLength)

        // message type (1 byte)
        buffer.write(messageType)

        // payload
        buffer.write(payload)

        // padding (random bytes)
        val padding = securePadding(paddingLength)
        buffer.write(padding)

        val data = buffer.toByteArray()
        return listOf(data)
    }

    private fun encodeEncryptedPacket(
        messageType: Int,
        payload: ByteArray,
        cipher: PacketCipher,
        mac: PacketMac,
        sequenceNumber: Long,
    ): List<ByteArray> {
        val payloadLength = 1 + payload.size
        val blockSize = cipher.blockSize

        // Calculate padding
        val paddingLength = calculatePaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // Build unencrypted packet
        val buffer = ByteArrayOutputStream(packetLength + 4)

        // packet_length (4 bytes)
        buffer.write(ByteBuffer.allocate(4).putInt(packetLength).array())

        // padding_length (1 byte)
        buffer.write(paddingLength)

        // message type (1 byte)
        buffer.write(messageType)

        // payload
        buffer.write(payload)

        // padding (random bytes)
        val padding = securePadding(paddingLength)
        buffer.write(padding)

        val unencryptedPacket = buffer.toByteArray()

        // Compute MAC before encryption (over plaintext)
        val macBytes = mac.compute(sequenceNumber, unencryptedPacket)

        // Encrypt packet
        val encryptedPacket = cipher.encrypt(unencryptedPacket)

        // Send encrypted packet + MAC
        val data = encryptedPacket + macBytes
        return listOf(data)
    }

    /**
     * Write an ETM (Encrypt-then-MAC) packet.
     *
     * In ETM mode, the length field is NOT encrypted, and MAC is computed over
     * (sequence_number || packet_length || encrypted_payload).
     */
    private fun encodeEtmPacket(
        messageType: Int,
        payload: ByteArray,
        cipher: PacketCipher,
        mac: PacketMac,
        sequenceNumber: Long,
    ): List<ByteArray> {
        val payloadLength = 1 + payload.size
        val blockSize = cipher.blockSize

        // Calculate padding (length field is not encrypted in ETM)
        val paddingLength = calculateAeadPaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // Build the payload to encrypt (padding_length + message type + payload + padding)
        val payloadBuffer = ByteArrayOutputStream(packetLength)
        payloadBuffer.write(paddingLength)
        payloadBuffer.write(messageType)
        payloadBuffer.write(payload)
        val padding = securePadding(paddingLength)
        payloadBuffer.write(padding)

        val payloadToEncrypt = payloadBuffer.toByteArray()

        // Encrypt payload (NOT including length)
        val encryptedPayload = cipher.encrypt(payloadToEncrypt)

        // Compute MAC over sequence_number || packet_length || encrypted_payload
        val macBytes = mac.computeEtm(sequenceNumber, packetLength, encryptedPayload)

        // Build final packet: length (unencrypted) + encrypted_payload + MAC
        val lengthBytes = ByteBuffer.allocate(4).putInt(packetLength).array()
        val data = ByteBuffer.allocate(lengthBytes.size + encryptedPayload.size + macBytes.size)
            .put(lengthBytes).put(encryptedPayload).put(macBytes).array()
        return listOf(data)
    }

    /**
     * Write an AEAD packet (e.g., AES-GCM per RFC 5647).
     *
     * Wire format: packet_length (4B, cleartext) || ciphertext || auth_tag (16B)
     * Plaintext: padding_length || message_type || payload || padding
     * Padding must align the plaintext to a 16-byte boundary.
     *
     * For ciphers that encrypt the length (e.g., ChaCha20-Poly1305):
     * Wire format: encrypted_length (4B) || ciphertext || auth_tag (16B)
     * The encrypted length bytes are passed as AAD to encrypt.
     */
    private fun encodeAeadPacket(
        messageType: Int,
        payload: ByteArray,
        aead: PacketAead,
        sequenceNumber: Long,
    ): List<ByteArray> {
        val payloadLength = 1 + payload.size // message type + payload
        val blockSize = if (aead.encryptsLength) 8 else 16

        val paddingLength = calculateAeadPaddingLength(payloadLength, blockSize)
        val packetLength = 1 + payloadLength + paddingLength

        // AES-GCM consumes these parts directly into its owned ciphertext/tag buffer.
        val plaintext = listOf(byteArrayOf(paddingLength.toByte(), messageType.toByte()), payload, securePadding(paddingLength))
        val lengthBytes = ByteBuffer.allocate(4).putInt(packetLength).array()

        val wireLength: ByteArray
        val aadBytes: ByteArray
        if (aead.encryptsLength) {
            wireLength = aead.encryptLength(sequenceNumber, lengthBytes)
            aadBytes = wireLength
        } else {
            wireLength = lengthBytes
            aadBytes = lengthBytes
        }

        val encrypted = aead.encryptPacket(aadBytes, plaintext)

        return listOf(wireLength, encrypted)
    }

    /**
     * Calculate padding length according to RFC 4253 section 6.
     *
     * The padding length must be such that:
     * - Total length (packet_length + 4 bytes) is a multiple of block size (or 8)
     * - Padding is at least 4 bytes
     * - Padding is less than 256 bytes
     */
    private fun calculatePaddingLength(payloadLength: Int, blockSize: Int): Int {
        val minBlockSize = maxOf(8, blockSize)
        val totalLength = 4 + 1 + payloadLength // length field + padding_length + payload

        // Find padding that makes total length a multiple of block size
        var paddingLength = minBlockSize - (totalLength % minBlockSize)

        // Ensure minimum padding of 4 bytes
        if (paddingLength < 4) {
            paddingLength += minBlockSize
        }

        return paddingLength
    }

    private fun securePadding(length: Int): ByteArray = ByteArray(length).also(secureRandom::nextBytes)

    /**
     * Calculate padding length for ETM/AEAD packets.
     *
     * For ETM and AEAD, the 4-byte length field is not encrypted, so alignment
     * is on the encrypted portion (padding_length + payload + padding) only.
     */
    private fun calculateAeadPaddingLength(payloadLength: Int, blockSize: Int): Int {
        val contentLength = 1 + payloadLength // padding_length byte + payload
        val slack = contentLength % blockSize
        var paddingLength = if (slack == 0) 0 else blockSize - slack

        if (paddingLength < 4) {
            paddingLength += blockSize
        }

        return paddingLength
    }

    /**
     * Read the SSH version banner (plain text before packet protocol).
     *
     * @return Parsed banner
     */
    suspend fun readBanner(): IdBanner {
        val bannerBytes = ByteArrayOutputStream()
        var expectLf = false

        // Try to be compatible with non-standard servers: LF or CRLF.
        // After CR, only further CRs and the terminating LF are permitted.
        while (true) {
            val byte = transport.read(1)[0]
            bannerBytes.write(byte.toInt())

            // RFC 4253 section 4.2 includes the terminator in the 255-byte limit.
            if (bannerBytes.size() > 255) {
                throw TransportException("Banner too long")
            }
            if (byte == '\n'.code.toByte()) break
            if (byte == '\r'.code.toByte()) {
                expectLf = true
            } else if (byte == 0.toByte() || expectLf) {
                throw TransportException("Malformed SSH identification")
            }
        }

        val bytes = bannerBytes.toByteArray()
        val stream = ByteBufferKaitaiStream(bytes)
        val banner = IdBanner(stream)
        try {
            banner._read()
        } catch (e: RuntimeException) {
            val parseFailure = e.kaitaiParseFailureOrNull() ?: throw e
            throw TransportException("Malformed SSH identification", parseFailure)
        }
        return banner
    }

    /**
     * Write the SSH version banner.
     *
     * @param version Version string (e.g., "SSH-2.0-MyClient_1.0")
     */
    suspend fun writeBanner(version: String) {
        val banner = "$version\r\n"
        transport.write(banner.toByteArray(Charsets.US_ASCII))
    }
}
