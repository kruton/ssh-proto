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
import org.connectbot.sshlib.protocol.SshHybridKexBlob
import org.connectbot.sshlib.protocol.toByteArray
import java.security.MessageDigest

internal enum class MlKemNistParameters(
    val mlKem: MlKemParameterSet,
    val curveName: String,
    val fieldSize: Int,
    val hashAlgorithm: String,
) {
    NISTP256(MlKemParameterSet.ML_KEM_768, "nistp256", 32, "SHA-256"),
    NISTP384(MlKemParameterSet.ML_KEM_1024, "nistp384", 48, "SHA-384"),
}

/** RFC 10042 sections 2.3.1 and 2.3.2, using Android-compatible ML-KEM and JCA ECDH. */
internal class MlKemNistHybridKeyExchange(
    private val parameters: MlKemNistParameters,
    private val mlKemProvider: MlKemProvider = MlKemProviderFactory.forParameterSet(parameters.mlKem),
) : KexAlgorithm {
    override val hashAlgorithm: String = parameters.hashAlgorithm
    private val ecdh = EcdhKeyExchange(parameters.curveName)
    private var mlKemPrivateKey: ByteArray? = null
    private val ecPublicKeySize = 1 + 2 * parameters.fieldSize

    override fun generateClientKeys(): ByteArray {
        zeroize()
        try {
            val keys = mlKemProvider.generateKeyPair()
            mlKemPrivateKey = keys.privateKey
            if (keys.publicKey.size != parameters.mlKem.publicKeySize) {
                throw SshException("Unexpected ${parameters.mlKem} public key length: ${keys.publicKey.size}")
            }
            val classicalPublic = ecdh.generateClientKeys()
            if (classicalPublic.size != ecPublicKeySize) throw SshException("Invalid ECDH public key length")
            return SshHybridKexBlob(parameters.mlKem.publicKeySize.toLong(), ecPublicKeySize.toLong()).apply {
                setPqData(keys.publicKey)
                setClassicalData(classicalPublic)
            }.toByteArray()
        } catch (e: Exception) {
            zeroize()
            if (e is SshException) throw e
            throw SshException("ML-KEM/NIST hybrid key generation failed", e)
        }
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val privateKey = mlKemPrivateKey
            ?: throw SshException("Client keys not generated; call generateClientKeys() first")
        val ciphertextSize = parameters.mlKem.ciphertextSize
        val expectedSize = ciphertextSize + ecPublicKeySize
        // Check the complete blob before either decapsulation or ECDH.
        if (serverPublicKey.size != expectedSize) {
            throw SshException("Invalid S_REPLY length: ${serverPublicKey.size} (expected $expectedSize)")
        }
        var classicalSecret: ByteArray? = null
        var pqSecret: ByteArray? = null
        try {
            val reply = SshHybridKexBlob(ByteBufferKaitaiStream(serverPublicKey), ciphertextSize.toLong(), ecPublicKeySize.toLong()).apply { _read() }
            classicalSecret = ecdh.computeRawSharedSecret(reply.classicalData())
            pqSecret = mlKemProvider.decapsulate(privateKey, reply.pqData())
            return combineSharedSecrets(pqSecret, classicalSecret)
        } catch (e: Exception) {
            if (e is SshException) throw e
            throw SshException("ML-KEM/NIST hybrid key exchange failed", e)
        } finally {
            pqSecret?.fill(0)
            classicalSecret?.fill(0)
        }
    }

    internal fun combineSharedSecrets(pqSecret: ByteArray, classicalSecret: ByteArray): ByteArray {
        var nonZero = 0
        for (byte in classicalSecret) nonZero = nonZero or byte.toInt()
        if (pqSecret.size != 32 || classicalSecret.size != parameters.fieldSize || nonZero == 0) {
            throw SshException("Invalid ML-KEM/NIST shared secret length or all-zero ECDH secret")
        }
        // RFC 10042 section 2.4: fixed-width octet strings, never mpint/sign padding.
        val combined = pqSecret + classicalSecret
        return try {
            encodeSshString(MessageDigest.getInstance(hashAlgorithm).digest(combined))
        } finally {
            combined.fill(0)
        }
    }

    override fun zeroize() {
        mlKemPrivateKey?.fill(0)
        mlKemPrivateKey = null
        ecdh.zeroize()
    }
}
