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

package org.connectbot.sshlib.struct

/**
 * Example SSH client demonstrating the use of SshClientStateMachine.
 *
 * This is a minimal example showing how to use the client state machine with
 * the callback interface. In a real implementation, you would:
 * - Implement actual network I/O
 * - Perform cryptographic operations
 * - Handle authentication
 * - Manage channels
 */
class ExampleSshClient : SshClientCallbacks {
    val stateMachine = SshClientStateMachine(this)

    fun connect() {
        println("Starting SSH connection...")
        stateMachine.processEvent(SshClientStateMachine.SshEvent.Connect)
    }

    // Version exchange
    override fun sendVersion() {
        println("Sending version: SSH-2.0-ExampleClient_1.0")
        // In real implementation: send "SSH-2.0-ExampleClient_1.0\r\n" to socket
    }

    override fun receiveVersion(banner: Ssh.IdBanner) {
        println("Received server version: ${banner.protoVersion()}")
        // In real implementation: parse banner from socket
    }

    // Key exchange initialization
    override fun sendKexInit() {
        println("Sending KEX_INIT with algorithm preferences")
        // In real implementation: send SSH_MSG_KEXINIT with preferred algorithms
    }

    override fun receiveKexInit(msg: Ssh.SshMsgKexinit) {
        println("Received KEX_INIT from server")
        println("  Server host key algorithms: ${msg.serverHostKeyAlgorithms()}")
        println("  Encryption algorithms c->s: ${msg.encryptionAlgorithmsClientToServer()}")
        // In real implementation: negotiate algorithms with server's preferences
    }

    // Key exchange
    override fun sendKexDhInit() {
        println("Sending DH_INIT with client's public key")
        // In real implementation: generate ephemeral key pair and send public key
    }

    override fun receiveKexDhReply(msg: Ssh.SshMsgKexdhReply) {
        println("Received DH_REPLY from server")
        println("  Server public host key length: ${msg.serverKey().data().size} bytes")
        // In real implementation:
        // - Extract server's public key and signature
        // - Compute shared secret
        // - Verify server's signature
    }

    override fun receiveKexEcdhReply(msg: Ssh.SshMsgKexEcdhReply) {
        println("Received ECDH_REPLY from server")
        // Similar to DH but with elliptic curve cryptography
    }

    override fun receiveKexDhGexReply(msg: Ssh.SshMsgKexDhGexReply) {
        println("Received DH_GEX_REPLY from server")
        // Diffie-Hellman Group Exchange variant
    }

    // New keys
    override fun sendNewKeys() {
        println("Sending NEW_KEYS")
        // In real implementation: send SSH_MSG_NEWKEYS
    }

    override fun receiveNewKeys() {
        println("Received NEW_KEYS from server")
    }

    override fun activateEncryption() {
        println("Activating encryption with negotiated algorithms")
        // In real implementation:
        // - Derive encryption/MAC keys from shared secret
        // - Initialize cipher and MAC
        // - All subsequent packets are encrypted
    }

    // Service request
    override fun sendServiceRequest(service: String) {
        println("Requesting service: $service")
        // In real implementation: send SSH_MSG_SERVICE_REQUEST
    }

    override fun receiveServiceAccept(service: String) {
        println("Service accepted: $service")
    }

    // Authentication
    override fun startAuthentication() {
        println("Starting authentication")
        // In real implementation: send SSH_MSG_USERAUTH_REQUEST with credentials
    }

    override fun authenticationSuccess() {
        println("Authentication successful!")
    }

    override fun authenticationFailure() {
        println("Authentication failed")
    }

    // Debug/control messages
    override fun debug(msg: Ssh.SshMsgDebug) {
        println("Debug message: ${msg.message()}")
    }

    override fun ignore() {
        println("Received IGNORE message")
    }

    override fun disconnect() {
        println("Disconnecting...")
    }

    // State transitions
    override fun onStateEnter(stateName: String) {
        println("[STATE] Entering: $stateName")
    }

    override fun onStateExit(stateName: String) {
        println("[STATE] Exiting: $stateName")
    }
}

/**
 * Example usage pattern:
 *
 * ```kotlin
 * val client = ExampleSshClient()
 * client.connect()
 *
 * // When you receive data from the network:
 * val banner = Ssh.IdBanner(ByteBufferKaitaiStream(bannerBytes))
 * client.stateMachine.processEvent(
 *     SshClientStateMachine.SshEvent.ReceiveVersion(banner)
 * )
 *
 * // When you parse a KEX_INIT message:
 * val packet = Ssh.UnencryptedPacket(ByteBufferKaitaiStream(packetBytes))
 * val kexInit = packet.payload().body() as Ssh.SshMsgKexinit
 * client.stateMachine.processEvent(
 *     SshClientStateMachine.SshEvent.ReceiveKexInit(kexInit)
 * )
 *
 * // Continue with other events as messages are received...
 * ```
 *
 * See CaptureTest.java for a complete example of parsing SSH protocol messages.
 */
