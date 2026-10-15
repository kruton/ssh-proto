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

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.crypto.sntrup.Sntrup761KeyPair
import org.connectbot.sshlib.protocol.SshHybridKexBlob
import org.connectbot.sshlib.protocol.toByteArray
import java.security.MessageDigest

/** RFC 9941: SNTRUP761 + X25519, with the SHA-512 output encoded as an SSH string. */
internal class SntrupHybridKeyExchange(
    private val x25519Provider: X25519Provider = X25519ProviderFactory.provider,
) : KexAlgorithm {
    override val hashAlgorithm: String = "SHA-512"

    private var sntrupKeys: Sntrup761KeyPair? = null
    private var x25519PrivateKey: ByteArray? = null

    override fun generateClientKeys(): ByteArray {
        zeroize()
        try {
            val keys = Sntrup761KeyPair.generate()
            sntrupKeys = keys
            val privateKey = x25519Provider.generatePrivateKey()
            x25519PrivateKey = privateKey
            val publicKey = x25519Provider.publicFromPrivate(privateKey)
            if (keys.publicKey.size != 1158 || publicKey.size != 32) {
                throw SshException("Invalid SNTRUP761/X25519 public key length")
            }
            return SshHybridKexBlob(1158.toLong(), 32.toLong()).apply {
                setPqData(keys.publicKey)
                setClassicalData(publicKey)
            }.toByteArray()
        } catch (e: Exception) {
            zeroize()
            if (e is SshException) throw e
            throw SshException("SNTRUP hybrid key generation failed", e)
        }
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val keys = sntrupKeys ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        val privateKey = x25519PrivateKey ?: throw SshException("X25519 private key unavailable")
        if (serverPublicKey.size != 1071) {
            throw SshException("Invalid SNTRUP hybrid server key length: ${serverPublicKey.size} (expected 1071)")
        }
        var pqSecret: ByteArray? = null
        var ecSecret: ByteArray? = null
        var combined: ByteArray? = null
        try {
            val reply = SshHybridKexBlob(ByteBufferKaitaiStream(serverPublicKey), 1039, 32).apply { _read() }
            pqSecret = keys.decapsulate(reply.pqData())
            ecSecret = x25519Provider.computeSharedSecret(privateKey, reply.classicalData())
            if (pqSecret.size != 32 || ecSecret.size != 32) {
                throw SshException("Invalid SNTRUP761/X25519 shared secret length")
            }
            var nonZero = 0
            for (byte in ecSecret) nonZero = nonZero or byte.toInt()
            if (nonZero == 0) throw SshException("Invalid X25519 shared secret; all zeroes")
            // Preserve all 32 X25519 bytes, including leading zeros and the high bit.
            combined = pqSecret + ecSecret
            return encodeSshString(MessageDigest.getInstance(hashAlgorithm).digest(combined))
        } catch (e: Exception) {
            if (e is SshException) throw e
            throw SshException("SNTRUP hybrid key exchange failed", e)
        } finally {
            pqSecret?.fill(0)
            ecSecret?.fill(0)
            combined?.fill(0)
        }
    }

    override fun zeroize() {
        sntrupKeys?.clear()
        sntrupKeys = null
        x25519PrivateKey?.fill(0)
        x25519PrivateKey = null
    }
}
