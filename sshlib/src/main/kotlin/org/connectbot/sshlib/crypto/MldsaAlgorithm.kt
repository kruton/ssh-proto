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
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/** Platform-only ML-DSA support. The composite service performs the entire COMPSIG construction. */
internal enum class MldsaAlgorithm(
    val sshName: String,
    val jcaName: String,
    val publicKeySize: Int,
    val maxSignatureSize: Int,
    val oid: ByteArray,
) {
    MLDSA44("ssh-mldsa-44", "ML-DSA-44", 1312, 2420, byteArrayOf(0x60, 0x86.toByte(), 0x48, 1, 0x65, 3, 4, 3, 17)),
    MLDSA65("ssh-mldsa-65", "ML-DSA-65", 1952, 3309, byteArrayOf(0x60, 0x86.toByte(), 0x48, 1, 0x65, 3, 4, 3, 18)),
    MLDSA87("ssh-mldsa-87", "ML-DSA-87", 2592, 4627, byteArrayOf(0x60, 0x86.toByte(), 0x48, 1, 0x65, 3, 4, 3, 19)),
    MLDSA44_ED25519(
        "ssh-mldsa44-ed25519",
        "MLDSA44-Ed25519-SHA512",
        1344,
        2484,
        byteArrayOf(0x2b, 6, 1, 5, 5, 7, 6, 39),
    ),
    MLDSA87_P384(
        "ssh-mldsa87-p384",
        "MLDSA87-ECDSA-P384-SHA512",
        2689,
        4731,
        byteArrayOf(0x2b, 6, 1, 5, 5, 7, 6, 49),
    ),
    ;

    val isComposite: Boolean get() = this == MLDSA44_ED25519 || this == MLDSA87_P384

    // Android providers may expose only the generic service, with the parameter set taken from the key.
    private val serviceNames = if (jcaName.startsWith("ML-DSA-")) listOf(jcaName, "ML-DSA") else listOf(jcaName)

    fun subjectPublicKeyInfo(rawKey: ByteArray): ByteArray {
        if (rawKey.size != publicKeySize) throw SshException("Invalid $sshName public key size: ${rawKey.size}")
        return encodeDer {
            sequence {
                sequence { objectIdentifier(oid) }
                bitString(rawKey)
            }
        }
    }

    /** Try key conversion and signature initialization together, including Android raw-key restrictions. */
    fun verifier(rawKey: ByteArray, providers: List<Provider> = Security.getProviders().toList()): Signature {
        val spec = X509EncodedKeySpec(subjectPublicKeyInfo(rawKey))
        var lastFailure: Exception? = null
        for (provider in providers) {
            for (factoryName in serviceNames) {
                for (signatureName in serviceNames) {
                    try {
                        val key = KeyFactory.getInstance(factoryName, provider).generatePublic(spec)
                        return Signature.getInstance(signatureName, provider).apply { initVerify(key) }
                    } catch (e: GeneralSecurityException) {
                        lastFailure = e
                    } catch (e: RuntimeException) {
                        // Provider implementations can reject non-keystore keys with unchecked exceptions.
                        lastFailure = e
                    }
                }
            }
        }
        throw SshException("No installed provider can verify $sshName", lastFailure)
    }

    fun signer(privateKey: PrivateKey, providers: List<Provider> = Security.getProviders().toList()): Signature {
        var lastFailure: Exception? = null
        for (provider in providers) {
            for (name in serviceNames) {
                try {
                    return Signature.getInstance(name, provider).apply { initSign(privateKey) }
                } catch (e: GeneralSecurityException) {
                    lastFailure = e
                } catch (e: RuntimeException) {
                    lastFailure = e
                }
            }
        }
        throw SshException("No installed provider can sign $sshName with this key", lastFailure)
    }

    fun importKeyPair(rawPublicKey: ByteArray, privateEncoding: ByteArray): KeyPair {
        var lastFailure: Exception? = null
        for (provider in Security.getProviders()) {
            for (name in serviceNames) {
                try {
                    val factory = KeyFactory.getInstance(name, provider)
                    val pair = KeyPair(
                        factory.generatePublic(X509EncodedKeySpec(subjectPublicKeyInfo(rawPublicKey))),
                        factory.generatePrivate(PKCS8EncodedKeySpec(privateEncoding)),
                    )
                    // Reject a public key that does not belong to the supplied private key.
                    val challenge = "cbssh private key consistency".toByteArray(Charsets.US_ASCII)
                    val signer = signer(pair.private, listOf(provider))
                    signer.update(challenge)
                    val signature = signer.sign()
                    val verifier = verifier(rawPublicKey, listOf(provider))
                    verifier.update(challenge)
                    if (!verifier.verify(signature)) throw SshException("$sshName public and private keys do not match")
                    return pair
                } catch (e: SshException) {
                    lastFailure = e
                } catch (e: GeneralSecurityException) {
                    lastFailure = e
                } catch (e: RuntimeException) {
                    lastFailure = e
                }
            }
        }
        throw SshException("No installed provider can import $sshName key material", lastFailure)
    }

    fun isAvailable(providers: List<Provider> = Security.getProviders().toList()): Boolean = try {
        // Any t1 coefficients encode an ML-DSA public key. Use a valid Ed25519 point for the composite.
        val rawKey = ByteArray(publicKeySize)
        if (this == MLDSA44_ED25519) {
            val ed25519 = byteArrayOf(
                0xd7.toByte(), 0x5a, 0x98.toByte(), 1, 0x82.toByte(), 0xb1.toByte(), 0x0a, 0xb7.toByte(),
                0xd5.toByte(), 0x4b, 0xfe.toByte(), 0xd3.toByte(), 0xc9.toByte(), 0x64, 7, 0x3a,
                0x0e, 0xe1.toByte(), 0x72, 0xf3.toByte(), 0xda.toByte(), 0xa6.toByte(), 0x23, 0x25,
                0xaf.toByte(), 2, 0x1a, 0x68, 0xf7.toByte(), 7, 0x51, 0x1a,
            )
            ed25519.copyInto(rawKey, 1312)
        }
        if (this == MLDSA87_P384) {
            // A valid public P-384 base point lets providers validate the entire composite key.
            val x = java.math.BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16)
            val y = java.math.BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)
            rawKey[2592] = 4
            x.toByteArray().takeLast(48).toByteArray().copyInto(rawKey, 2593)
            y.toByteArray().takeLast(48).toByteArray().copyInto(rawKey, 2641)
        }
        verifier(rawKey, providers)
        true
    } catch (_: SshException) {
        false
    }

    companion object {
        fun fromSshName(name: String): MldsaAlgorithm? = entries.firstOrNull { it.sshName == name }

        fun fromOid(oid: ByteArray): MldsaAlgorithm? = entries.firstOrNull { it.oid.contentEquals(oid) }

        fun isMldsaKey(key: PublicKey): Boolean = key.algorithm.startsWith("ML-DSA", ignoreCase = true) ||
            key.algorithm.startsWith("MLDSA", ignoreCase = true) ||
            key.algorithm.startsWith("COMPSIG-MLDSA", ignoreCase = true)

        /** Read the OID, not encoded-key length or provider-specific key classes. */
        fun decodePublicKey(key: PublicKey): Pair<MldsaAlgorithm, ByteArray> {
            val encoding = key.encoded ?: throw SshException("ML-DSA public key is not exportable")
            val reader = DerReader(encoding)
            val decoded = reader.readSequence { spki ->
                val algorithm = spki.readSequence { identifier ->
                    val oid = identifier.readObjectIdentifier()
                    entries.firstOrNull { it.oid.contentEquals(oid) }
                        ?: throw SshException("Unsupported ML-DSA public key algorithm identifier")
                }
                val raw = spki.readBitString()
                if (raw.size != algorithm.publicKeySize) throw SshException("Invalid ${algorithm.sshName} public key size: ${raw.size}")
                algorithm to raw
            }
            reader.ensureFullyConsumed()
            return decoded
        }
    }
}
