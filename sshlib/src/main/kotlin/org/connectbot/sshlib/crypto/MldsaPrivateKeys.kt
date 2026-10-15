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

import org.connectbot.sshlib.SshException
import java.math.BigInteger
import java.security.KeyPair

/** Standard PKCS#8 / RFC 5958 encodings and OpenSSH's composite seed representation. */
internal object MldsaPrivateKeys {
    private data class Parts(val parameter: MldsaAlgorithm, val privateKey: ByteArray, val publicKey: ByteArray?)

    private fun parse(data: ByteArray): Parts? {
        val reader = DerReader(data)
        val result = reader.readSequence { seq ->
            val version = seq.readInteger()
            val parameter = seq.readSequence { identifier ->
                val algorithm = MldsaAlgorithm.fromOid(identifier.readObjectIdentifier())
                if (algorithm == null) while (identifier.hasRemaining()) identifier.skipTag()
                algorithm
            }
            if (parameter == null) {
                while (seq.hasRemaining()) seq.skipTag()
                null
            } else {
                if (version != BigInteger.ZERO && version != BigInteger.ONE) throw SshException("Invalid ML-DSA PKCS#8 version")
                val privateKey = seq.readOctetString()
                if (seq.peekTag() == 0xa0) seq.skipTag() // Optional attributes.
                val publicKey = if (seq.peekTag() == 0x81) {
                    val bits = seq.readPrimitiveContextTag(1)
                    if (bits.isEmpty() || bits[0] != 0.toByte()) throw SshException("Invalid ML-DSA public-key BIT STRING")
                    bits.copyOfRange(1, bits.size)
                } else {
                    null
                }
                if ((publicKey != null) != (version == BigInteger.ONE)) throw SshException("ML-DSA PKCS#8 version does not match public-key field")
                Parts(parameter, privateKey, publicKey)
            }
        }
        reader.ensureFullyConsumed()
        return result
    }

    private fun encode(parameter: MldsaAlgorithm, privateKey: ByteArray, publicKey: ByteArray? = null): ByteArray = encodeDer {
        sequence {
            integer(if (publicKey == null) BigInteger.ZERO else BigInteger.ONE)
            sequence { objectIdentifier(parameter.oid) }
            octetString(privateKey)
            if (publicKey != null) primitiveContextTag(1, byteArrayOf(0) + publicKey)
        }
    }

    fun readPem(data: ByteArray, companionPublicKey: ByteArray?): SshPrivateKey? {
        val parts = parse(data) ?: return null
        val companion = companionPublicKey?.let { encoding ->
            val reader = DerReader(encoding)
            val raw = reader.readSequence { seq ->
                seq.readSequence { identifier ->
                    if (MldsaAlgorithm.fromOid(identifier.readObjectIdentifier()) != parts.parameter) {
                        throw SshException("ML-DSA public and private key algorithms do not match")
                    }
                }
                seq.readBitString()
            }
            reader.ensureFullyConsumed()
            raw
        }
        if (parts.publicKey != null && companion != null && !parts.publicKey.contentEquals(companion)) {
            throw SshException("Conflicting ML-DSA public keys in PEM")
        }
        val rawPublic = parts.publicKey ?: companion
            ?: throw SshException("ML-DSA PKCS#8 requires an embedded public key or an accompanying PUBLIC KEY PEM block")
        val pair = parts.parameter.importKeyPair(rawPublic, encode(parts.parameter, parts.privateKey))
        return SshPrivateKey(parts.parameter.sshName, pair, parts.parameter.sshName)
    }

    fun writePem(keyPair: KeyPair): ByteArray {
        val (parameter, rawPublic) = MldsaAlgorithm.decodePublicKey(keyPair.public)
        val parts = parse(exportableEncoding(keyPair)) ?: throw SshException("Not an ML-DSA private key")
        if (parts.parameter != parameter) throw SshException("ML-DSA public and private key algorithms do not match")
        parameter.importKeyPair(rawPublic, encode(parameter, parts.privateKey))
        return encode(parameter, parts.privateKey, rawPublic)
    }

    fun readOpenSsh(rawPublic: ByteArray, seeds: ByteArray): KeyPair {
        if (seeds.size != 64) throw SshException("OpenSSH composite private key must contain two 32-byte seeds")
        val parameter = MldsaAlgorithm.MLDSA44_ED25519
        return parameter.importKeyPair(rawPublic, encode(parameter, seeds))
    }

    fun openSshSeeds(keyPair: KeyPair): ByteArray {
        val parts = parse(exportableEncoding(keyPair)) ?: throw SshException("Not an ML-DSA private key")
        if (parts.parameter != MldsaAlgorithm.MLDSA44_ED25519 || parts.privateKey.size != 64) {
            throw SshException("OpenSSH requires an ML-DSA-44/Ed25519 composite key with exportable seeds")
        }
        val rawPublic = MldsaAlgorithm.decodePublicKey(keyPair.public).second
        readOpenSsh(rawPublic, parts.privateKey)
        return parts.privateKey
    }

    private fun exportableEncoding(keyPair: KeyPair): ByteArray = try {
        if (keyPair.private.format != "PKCS#8") throw SshException("ML-DSA private key is not exportable as PKCS#8")
        keyPair.private.encoded ?: throw SshException("ML-DSA private key is not exportable")
    } catch (e: RuntimeException) {
        throw SshException("ML-DSA private key is not exportable", e)
    }
}
