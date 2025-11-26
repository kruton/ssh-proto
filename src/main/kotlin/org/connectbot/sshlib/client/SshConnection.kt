/*
 * Copyright 2025 Kenny Root
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

package org.connectbot.sshlib.client

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.crypto.*
import org.connectbot.sshlib.struct.Ssh
import org.connectbot.sshlib.struct.SshClientCallbacks
import org.connectbot.sshlib.struct.SshClientStateMachine
import org.connectbot.sshlib.transport.PacketIO
import org.connectbot.sshlib.transport.Transport
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * SSH connection handler that manages the protocol flow.
 *
 * This class ties together the state machine, transport layer, and crypto
 * implementations to handle a complete SSH connection lifecycle.
 *
 * @param transport Underlying transport (e.g., TCP socket)
 * @param clientVersion Client version string (default: SSH-2.0-SshProtoClient_1.0)
 */
class SshConnection(
    private val transport: Transport,
    private val clientVersion: String = "SSH-2.0-SshProtoClient_1.0"
) : SshClientCallbacks {

    companion object {
        private val logger = LoggerFactory.getLogger(SshConnection::class.java)

        // Supported algorithms (minimal initial implementation)
        // Note: kex-strict-c-v00@openssh.com is a marker for strict KEX support (RFC draft-ietf-sshm-strict-kex)
        private const val KEX_ALGORITHMS = "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,kex-strict-c-v00@openssh.com"
        private const val HOST_KEY_ALGORITHMS = "rsa-sha2-256,rsa-sha2-512,ssh-rsa"
        private const val ENCRYPTION_ALGORITHMS = "aes128-ctr,aes256-ctr"
        private const val MAC_ALGORITHMS = "hmac-sha2-256,hmac-sha2-512"
        private const val COMPRESSION_ALGORITHMS = "none"
    }

    private val packetIO = PacketIO(transport)
    private val stateMachine = SshClientStateMachine(this)

    private var serverVersion: String? = null
    private var clientKexInit: ByteArray? = null
    private var serverKexInit: ByteArray? = null

    private val dh = DiffieHellman()
    private var clientPublicKey: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var exchangeHash: ByteArray? = null
    private var sessionId: ByteArray? = null

    /**
     * Initiate SSH connection.
     * This is a blocking call that returns when authentication is complete.
     */
    fun connect(): Boolean = runBlocking {
        try {
            stateMachine.processEvent(SshClientStateMachine.SshEvent.Connect)

            // Version exchange
            packetIO.writeBanner(clientVersion)
            val banner = packetIO.readBanner()
            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveVersion(banner))
            // Note: ReceiveVersion transition triggers sendKexInit() via state machine

            // Key exchange initialization - read server's KEXINIT
            val kexInitPacket = packetIO.readPacket()
            val kexInit = kexInitPacket.body() as Ssh.SshMsgKexinit

            // Save raw KEXINIT payload for exchange hash (message type + body)
            val kexInitMsgType = kexInitPacket.messageType().id().toByte()
            serverKexInit = byteArrayOf(kexInitMsgType) + kexInitPacket._raw_body()

            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveKexInit(kexInit))
            // Note: ReceiveKexInit transition triggers sendKexDhInit() via state machine

            // Diffie-Hellman key exchange - read server's DH_REPLY
            // KEX-specific messages (30-49) need special parsing based on negotiated algorithm
            val dhReplyPacket = packetIO.readPacket()

            // Re-parse as KEXDH payload since we negotiated diffie-hellman-group14
            // _raw_body() excludes the message type byte, so we need to prepend it
            val messageTypeByte = dhReplyPacket.messageType().id().toByte()
            val rawBody = byteArrayOf(messageTypeByte) + dhReplyPacket._raw_body()
            val kexdhStream = io.kaitai.struct.ByteBufferKaitaiStream(rawBody)
            val kexdhPayload = Ssh.KexdhPayload(kexdhStream)
            kexdhPayload._read()
            val dhReply = kexdhPayload.body() as Ssh.SshMsgKexdhReply

            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveKex.DhReply(dhReply))
            // Note: ReceiveKex.DhReply transition triggers sendNewKeys() via state machine

            // New keys - read server's NEWKEYS
            val newKeysPacket = packetIO.readPacket()
            stateMachine.processEvent(SshClientStateMachine.SshEvent.ReceiveNewKeys)

            // Service request (ssh-userauth)
            // Loop until we get SERVICE_ACCEPT (skip IGNORE/DEBUG messages)
            val serviceAccept = readExpectedMessage<Ssh.SshMsgServiceAccept>(
                Ssh.MessageType.SSH_MSG_SERVICE_ACCEPT
            )
            stateMachine.processEvent(
                SshClientStateMachine.SshEvent.ReceiveServiceAccept(serviceAccept.serviceName().value())
            )

            logger.info("SSH connection established successfully")
            return@runBlocking true
        } catch (e: Exception) {
            logger.error("SSH connection failed", e)
            return@runBlocking false
        }
    }

    /**
     * Authenticate using password.
     *
     * @param username Username
     * @param password Password
     * @return true if authentication succeeded
     */
    suspend fun authenticatePassword(username: String, password: String): Boolean {
        try {
            // Build SSH_MSG_USERAUTH_REQUEST packet
            val buffer = ByteArrayOutputStream()

            // user name (string)
            writeString(buffer, username.toByteArray())

            // service name (string) - always "ssh-connection"
            writeString(buffer, "ssh-connection".toByteArray())

            // method name (string) - "password"
            writeString(buffer, "password".toByteArray())

            // FALSE (boolean) - not changing password
            buffer.write(0)

            // password (string)
            writeString(buffer, password.toByteArray())

            val payload = buffer.toByteArray()
            packetIO.writePacket(Ssh.MessageType.SSH_MSG_USERAUTH_REQUEST.id().toInt(), payload)

            // Wait for response
            val response = packetIO.readPacket()
            return when (response.messageType()) {
                Ssh.MessageType.SSH_MSG_USERAUTH_SUCCESS -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.AuthenticationSuccess)
                    logger.info("Authentication successful")
                    true
                }
                Ssh.MessageType.SSH_MSG_USERAUTH_FAILURE -> {
                    stateMachine.processEvent(SshClientStateMachine.SshEvent.AuthenticationFailure)
                    logger.warn("Authentication failed")
                    false
                }
                else -> {
                    logger.warn("Unexpected message type during auth: ${response.messageType()}")
                    false
                }
            }
        } catch (e: Exception) {
            logger.error("Authentication error", e)
            return false
        }
    }

    // SshClientCallbacks implementation

    override fun sendVersion() {
        logger.debug("Sending version: $clientVersion")
    }

    override fun receiveVersion(banner: Ssh.IdBanner) {
        // protoVersion() includes everything after "SSH-" up to and including \r\n
        // For exchange hash, we need "SSH-" + version without the CR-LF
        val versionWithCrlf = banner.protoVersion()
        val versionClean = versionWithCrlf.trimEnd('\r', '\n')
        serverVersion = "SSH-$versionClean"
        logger.info("Server version: $serverVersion")
    }

    override fun sendKexInit() {
        logger.debug("Sending KEX_INIT")

        val buffer = ByteArrayOutputStream()

        // Cookie (16 random bytes)
        val cookie = ByteArray(16).apply {
            java.security.SecureRandom().nextBytes(this)
        }
        buffer.write(cookie)

        // Algorithm name-lists
        writeNameList(buffer, KEX_ALGORITHMS)
        writeNameList(buffer, HOST_KEY_ALGORITHMS)
        writeNameList(buffer, ENCRYPTION_ALGORITHMS)
        writeNameList(buffer, ENCRYPTION_ALGORITHMS)
        writeNameList(buffer, MAC_ALGORITHMS)
        writeNameList(buffer, MAC_ALGORITHMS)
        writeNameList(buffer, COMPRESSION_ALGORITHMS)
        writeNameList(buffer, COMPRESSION_ALGORITHMS)
        writeNameList(buffer, "") // languages client-to-server
        writeNameList(buffer, "") // languages server-to-client

        // first_kex_packet_follows (boolean) - FALSE
        buffer.write(0)

        // reserved (uint32) - 0
        buffer.write(ByteArray(4))

        // Save the payload (without message type)
        val kexInitPayload = buffer.toByteArray()

        // For exchange hash, we need message type (20) + payload
        clientKexInit = byteArrayOf(Ssh.MessageType.SSH_MSG_KEXINIT.id().toByte()) + kexInitPayload

        runBlocking {
            packetIO.writePacket(Ssh.MessageType.SSH_MSG_KEXINIT.id().toInt(), kexInitPayload)
        }
    }

    override fun receiveKexInit(msg: Ssh.SshMsgKexinit) {
        logger.info("Received KEX_INIT from server")

        val serverKexAlgs = msg.kexAlgorithms().entries().data()
        val serverEncryptionAlgs = msg.encryptionAlgorithmsClientToServer().entries().data()
        val serverMacAlgs = msg.macAlgorithmsClientToServer().entries().data()

        logger.debug("  Server KEX algorithms: $serverKexAlgs")
        logger.debug("  Server encryption c->s: $serverEncryptionAlgs")
        logger.debug("  Server MAC c->s: $serverMacAlgs")

        // Find first matching KEX algorithm
        val clientKexList = KEX_ALGORITHMS.split(",")
        val matchingKex = clientKexList.firstOrNull { it in serverKexAlgs }
        logger.info("  Negotiated KEX: $matchingKex")

        if (matchingKex == null) {
            logger.error("No matching KEX algorithm! Client: $KEX_ALGORITHMS, Server: $serverKexAlgs")
        }
    }

    override fun sendKexDhInit() {
        logger.debug("Sending DH_INIT")

        // Generate client's DH key pair
        clientPublicKey = dh.generateClientKeys()

        // Build SSH_MSG_KEXDH_INIT packet
        val buffer = ByteArrayOutputStream()
        writeMpint(buffer, clientPublicKey!!)

        runBlocking {
            packetIO.writePacket(Ssh.KexDh.SSH_MSG_KEXDH_INIT.id().toInt(), buffer.toByteArray())
        }
    }

    override fun receiveKexDhReply(msg: Ssh.SshMsgKexdhReply) {
        logger.info("Received DH_REPLY from server")

        // Extract server's public key and signature
        val serverHostKey = msg.serverKey().data()
        val serverPublicKey = msg.f().body()
        val signature = msg.signatureH().data()

        // Compute shared secret
        sharedSecret = dh.computeSharedSecret(serverPublicKey)

        // Compute exchange hash
        exchangeHash = dh.computeExchangeHash(
            clientVersion.toByteArray(),
            serverVersion!!.toByteArray(),
            clientKexInit!!,
            serverKexInit!!,
            serverHostKey,
            clientPublicKey!!,
            serverPublicKey,
            sharedSecret!!
        )

        // Session ID is the exchange hash from first key exchange
        if (sessionId == null) {
            sessionId = exchangeHash
        }

        // TODO: Verify server's signature over exchange hash
        logger.debug("Shared secret computed, exchange hash calculated")
    }

    override fun receiveKexEcdhReply(msg: Ssh.SshMsgKexEcdhReply) {
        logger.warn("ECDH not implemented yet")
    }

    override fun receiveKexDhGexReply(msg: Ssh.SshMsgKexDhGexReply) {
        logger.warn("DH-GEX not implemented yet")
    }

    override fun sendNewKeys() {
        logger.debug("Sending NEW_KEYS")
        runBlocking {
            packetIO.writePacket(Ssh.MessageType.SSH_MSG_NEWKEYS.id().toInt())
            // TODO check if we're using strict KEX
            packetIO.resetSendSequenceNumber()
        }
    }

    override fun receiveNewKeys() {
        logger.info("Received NEW_KEYS from server")
        // TODO check if we're using strict KEX
        packetIO.resetReceiveSequenceNumber()
    }

    override fun activateEncryption() {
        logger.info("Activating encryption")

        // Derive keys using SHA-256 (for diffie-hellman-group14-sha256)
        val keyDerivation = KeyDerivation(
            sharedSecret!!,
            exchangeHash!!,
            sessionId!!,
            "SHA-256"
        )

        val keys = keyDerivation.deriveKeys(
            ivLength = 16,      // AES block size
            keyLength = 16,     // AES-128
            macKeyLength = 32   // HMAC-SHA256
        )


        // Create ciphers and MACs for both directions
        val clientToServerCipher = AesCtrCipher(keys.encryptionKeyClientToServer, keys.initialIvClientToServer, forEncryption = true)
        val clientToServerMac = HmacSha256(keys.integrityKeyClientToServer)
        val serverToClientCipher = AesCtrCipher(keys.encryptionKeyServerToClient, keys.initialIvServerToClient, forEncryption = false)
        val serverToClientMac = HmacSha256(keys.integrityKeyServerToClient)

        // Enable encryption in PacketIO
        packetIO.enableEncryption(
            clientToServerCipher,
            clientToServerMac,
            serverToClientCipher,
            serverToClientMac
        )

        logger.info("Encryption active")
    }

    override fun sendServiceRequest(service: String) {
        logger.info("Requesting service: $service")

        val buffer = ByteArrayOutputStream()
        writeString(buffer, service.toByteArray())

        runBlocking {
            packetIO.writePacket(Ssh.MessageType.SSH_MSG_SERVICE_REQUEST.id().toInt(), buffer.toByteArray())
        }
    }

    override fun receiveServiceAccept(service: String) {
        logger.info("Service accepted: $service")
    }

    override fun startAuthentication() {
        logger.info("Starting authentication")
    }

    override fun authenticationSuccess() {
        logger.info("Authentication successful")
    }

    override fun authenticationFailure() {
        logger.warn("Authentication failed")
    }

    override fun debug(msg: Ssh.SshMsgDebug) {
        logger.debug("SSH debug: ${msg.message()}")
    }

    override fun ignore() {
        logger.trace("Received IGNORE message")
    }

    override fun disconnect() {
        logger.info("Disconnecting")
        runBlocking {
            transport.close()
        }
    }

    override fun onStateEnter(stateName: String) {
        logger.debug("State: $stateName")
    }

    override fun onStateExit(stateName: String) {
        // Not logging state exits to reduce verbosity
    }

    // Helper methods for SSH protocol encoding

    /**
     * Read packets until we get the expected message type, skipping IGNORE/DEBUG messages.
     */
    private suspend inline fun <reified T> readExpectedMessage(expectedType: Ssh.MessageType): T {
        while (true) {
            val packet = packetIO.readPacket()
            val messageType = packet.messageType()

            when (messageType) {
                Ssh.MessageType.SSH_MSG_IGNORE -> {
                    logger.debug("Received SSH_MSG_IGNORE, skipping")
                    continue
                }
                Ssh.MessageType.SSH_MSG_DEBUG -> {
                    logger.debug("Received SSH_MSG_DEBUG, skipping")
                    continue
                }
                expectedType -> {
                    return packet.body() as T
                }
                else -> {
                    throw IllegalStateException("Expected $expectedType but got $messageType")
                }
            }
        }
    }

    private fun writeString(out: ByteArrayOutputStream, data: ByteArray) {
        val length = data.size
        out.write((length shr 24) and 0xFF)
        out.write((length shr 16) and 0xFF)
        out.write((length shr 8) and 0xFF)
        out.write(length and 0xFF)
        out.write(data)
    }

    private fun writeNameList(out: ByteArrayOutputStream, names: String) {
        writeString(out, names.toByteArray())
    }

    private fun writeMpint(out: ByteArrayOutputStream, data: ByteArray) {
        // Remove leading zeros
        var start = 0
        while (start < data.size - 1 && data[start] == 0.toByte()) {
            start++
        }

        // Check if we need to add 0x00 to keep it positive
        val needsPadding = data[start].toInt() and 0x80 != 0

        val length = data.size - start + if (needsPadding) 1 else 0
        out.write((length shr 24) and 0xFF)
        out.write((length shr 16) and 0xFF)
        out.write((length shr 8) and 0xFF)
        out.write(length and 0xFF)

        if (needsPadding) {
            out.write(0)
        }
        out.write(data, start, data.size - start)
    }
}
