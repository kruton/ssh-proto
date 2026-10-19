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

import io.kaitai.struct.ByteBufferKaitaiStream
import io.kaitai.struct.KaitaiStruct
import org.connectbot.sshlib.crypto.CERTIFICATE_SUFFIX
import org.connectbot.sshlib.protocol.SshKrl
import org.connectbot.sshlib.protocol.SshPublicKey
import java.math.BigInteger
import java.security.MessageDigest

/** An immutable OpenSSH KRL v1 loaded through an application-trusted channel. */
class SshKeyRevocationList private constructor(
    private val keys: List<ByteArray>,
    private val sha1: List<ByteArray>,
    private val sha256: List<ByteArray>,
    private val certificates: List<CertificateRule>,
) {
    /** Check a raw key or certificate, including revocation of its certified key or CA. */
    @Throws(SshException::class)
    fun isRevoked(key: PublicKey): Boolean = certificateInput("revocation query") {
        if (key.type.endsWith(CERTIFICATE_SUFFIX)) {
            val certificate = SshCertificate.decode(key.encoded)
            if (certificate.algorithmName != key.type) throw SshException("Certificate key type mismatch")
            isKeyRevoked(certificate.publicKey.encoded) || isKeyRevoked(certificate.signatureKey.encoded) ||
                certificates.any { it.matches(certificate) }
        } else {
            isKeyRevoked(key.encoded)
        }
    }

    private fun isKeyRevoked(blob: ByteArray): Boolean {
        if (keys.any { it.contentEquals(blob) }) return true
        if (sha1.isNotEmpty()) {
            // OpenSSH KRL SHA-1 entries only deny keys; a collision can reject an
            // additional key, but cannot authorize a key or bypass revocation.
            @Suppress("kotlin:S4790")
            val digest = MessageDigest.getInstance("SHA-1").digest(blob)
            if (sha1.any { it.contentEquals(digest) }) return true
        }
        if (sha256.isNotEmpty()) {
            val digest = MessageDigest.getInstance("SHA-256").digest(blob)
            if (sha256.any { it.contentEquals(digest) }) return true
        }
        return false
    }

    private class CertificateRule(val ca: ByteArray, val test: (SshCertificate) -> Boolean) {
        fun matches(certificate: SshCertificate): Boolean = (ca.isEmpty() || ca.contentEquals(certificate.signatureKey.encoded)) && test(certificate)
    }

    companion object {
        /** Decode a complete KRL. Malformed or unsupported lists throw; they never become empty lists. */
        @JvmStatic
        @Throws(SshException::class)
        fun decode(encoded: ByteArray): SshKeyRevocationList = certificateInput("key revocation list") {
            val wire = SshKrl(ByteBufferKaitaiStream(encoded.copyOf())).apply { _read() }
            val keys = mutableListOf<ByteArray>()
            val sha1 = mutableListOf<ByteArray>()
            val sha256 = mutableListOf<ByteArray>()
            val rules = mutableListOf<CertificateRule>()
            for (section in wire.sections()) {
                consumed(section.body())
                when (section.kind()) {
                    1 -> {
                        val certs = section.body() as SshKrl.Certificates
                        val ca = certs.caKey().data()
                        if (ca.isNotEmpty()) validateRawKey(ca)
                        if (certs.sections().isEmpty()) throw SshException("Empty KRL certificate section")
                        for (subsection in certs.sections()) {
                            val body = subsection.body()
                            consumed(body)
                            val predicate = certificateRule(body)
                            predicate?.let { rules.add(CertificateRule(ca, it)) }
                        }
                    }

                    2, 3, 5 -> {
                        val values = (section.body() as SshKrl.Strings).values().map { it.data() }
                        if (values.isEmpty()) throw SshException("Empty KRL key section")
                        if (section.kind() == 2) {
                            values.forEach(::validateRawKey)
                            keys.addAll(values)
                        } else {
                            val size = if (section.kind() == 3) 20 else 32
                            if (values.any { it.size != size } || values.zipWithNext().any { (a, b) -> BigInteger(1, a) >= BigInteger(1, b) }) {
                                throw SshException("Invalid KRL fingerprint section")
                            }
                            (if (size == 20) sha1 else sha256).addAll(values)
                        }
                    }

                    255 -> validateExtension(section.body() as SshKrl.Extension)

                    else -> throw SshException("Unsupported KRL section: ${section.kind()}")
                }
            }
            SshKeyRevocationList(keys, sha1, sha256, rules)
        }

        private fun certificateRule(body: Any?): ((SshCertificate) -> Boolean)? = when (body) {
            is SshKrl.SerialList -> {
                if (body.values().isEmpty()) throw SshException("Empty KRL serial list")
                val serials = body.values().map { it.toULong() }.toSet()
                if (0uL in serials) throw SshException("KRL serial zero is reserved")
                val matches: (SshCertificate) -> Boolean = { it.serial != 0uL && it.serial in serials }
                matches
            }

            is SshKrl.SerialRange -> {
                val first = body.first().toULong()
                val last = body.last().toULong()
                if (first == 0uL || first > last) throw SshException("Invalid KRL serial range")
                val matches: (SshCertificate) -> Boolean = { it.serial != 0uL && it.serial in first..last }
                matches
            }

            is SshKrl.SerialBitmap -> bitmapRule(body)

            is SshKrl.Strings -> {
                if (body.values().isEmpty()) throw SshException("Empty KRL key ID list")
                val ids = body.values().map { it.data() }
                val matches: (SshCertificate) -> Boolean = { cert -> ids.any { it.contentEquals(cert.keyIdBytes) } }
                matches
            }

            is SshKrl.Extension -> {
                validateExtension(body)
                null
            }

            else -> throw SshException("Unsupported KRL certificate section")
        }

        private fun bitmapRule(body: SshKrl.SerialBitmap): (SshCertificate) -> Boolean {
            val bytes = body.bitmap().body()
            val bitmap = if (bytes.isEmpty()) BigInteger.ZERO else BigInteger(bytes)
            if (bitmap.signum() < 0) throw SshException("Negative KRL bitmap")
            val offset = body.offset().toULong()
            if (offset == 0uL && bitmap.testBit(0)) throw SshException("KRL serial zero is reserved")
            if (bitmap.bitLength() > 0 && (bitmap.bitLength() - 1).toULong() > ULong.MAX_VALUE - offset) {
                throw SshException("KRL bitmap overflows serial range")
            }
            return { cert ->
                val delta = cert.serial - offset
                cert.serial != 0uL && cert.serial >= offset && delta < bitmap.bitLength().toULong() && bitmap.testBit(delta.toInt())
            }
        }

        private fun consumed(body: Any?) {
            if (body is KaitaiStruct && !body._io().isEof) throw SshException("Trailing bytes in KRL section")
        }

        private fun validateExtension(extension: SshKrl.Extension) {
            if (extension.name().data().isEmpty() || extension.critical() != 0) throw SshException("Unsupported critical KRL extension")
        }

        private fun validateRawKey(blob: ByteArray) {
            val stream = ByteBufferKaitaiStream(blob)
            val key = SshPublicKey(stream).apply { _read() }
            if (!stream.isEof || key.algorithmName().endsWith(CERTIFICATE_SUFFIX)) throw SshException("Expected a raw KRL public key")
        }
    }
}
