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
import org.connectbot.sshlib.crypto.Base64Compat
import org.connectbot.sshlib.crypto.certificateKeyTypes
import org.connectbot.sshlib.crypto.encodeSshString
import org.connectbot.sshlib.protocol.AsciiString
import org.connectbot.sshlib.protocol.EcdsaPublicKeyBlob
import org.connectbot.sshlib.protocol.SkEcdsaP256PublicKeyBlob
import org.connectbot.sshlib.protocol.SkEd25519PublicKeyBlob
import org.connectbot.sshlib.protocol.SshEd25519PublicKeyBlob
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshRsaPublicKeyBlob
import org.connectbot.sshlib.protocol.toByteArray
import java.util.Collections
import org.connectbot.sshlib.protocol.SshCertificate as WireCertificate

/** An OpenSSH v01 certificate. Decoding checks structure, but does not establish CA trust. */
class SshCertificate private constructor(
    private val bytes: ByteArray,
    private val wire: WireCertificate,
    private val key: PublicKey,
    private val authority: PublicKey,
) {
    enum class Type { USER, HOST }

    val type: Type get() = if (wire.certificateType() == 1L) Type.USER else Type.HOST
    val algorithmName: String get() = wire.algorithmName().value()

    /** Original SSH certificate wire blob. Returned byte arrays are independent copies. */
    val encoded: ByteArray get() = bytes.copyOf()

    /** Certified raw public key, including the application identifier for security keys. */
    val publicKey: PublicKey get() = key.copy(encoded = key.encoded.copyOf())

    /** Raw public key of the issuing certificate authority. */
    val signatureKey: PublicKey get() = authority.copy(encoded = authority.encoded.copyOf())

    /** CA-assigned unsigned serial number; zero means unassigned. */
    val serial: ULong get() = wire.serial().toULong()
    val keyId: String get() = wire.keyId().data().toString(Charsets.UTF_8)
    val principals: List<String> get() = Collections.unmodifiableList(wire.principals().values().map { it.data().toString(Charsets.UTF_8) })

    /** Inclusive validity start, in seconds since the Unix epoch. */
    val validAfter: ULong get() = wire.validAfter().toULong()

    /** Exclusive validity end, in seconds since the Unix epoch; ULong.MAX_VALUE means no expiry. */
    val validBefore: ULong get() = wire.validBefore().toULong()
    val criticalOptions: Map<String, ByteArray> get() = optionMap(wire.criticalOptions())
    val extensions: Map<String, ByteArray> get() = optionMap(wire.extensions())

    internal val signedBytes: ByteArray get() = bytes.copyOf(bytes.size - 4 - wire.signature().data().size)
    internal val signature: ByteArray get() = wire.signature().data().copyOf()
    internal val keyIdBytes: ByteArray get() = wire.keyId().data().copyOf()

    /** Return this user certificate for an external signer, including security-key signers. */
    @Throws(SshException::class)
    fun toAuthPublicKey(): AuthPublicKey {
        if (type != Type.USER) throw SshException("A host certificate cannot be used for user authentication")
        return AuthPublicKey(algorithmName, encoded)
    }

    companion object {
        /** Decode an OpenSSH certificate line, as produced in a `-cert.pub` file. */
        @JvmStatic
        @Throws(SshException::class)
        fun decode(text: String): SshCertificate = certificateInput("certificate") {
            val parts = text.trim().split(Regex("\\s+"), limit = 3)
            if (parts.size < 2) throw SshException("Expected an OpenSSH certificate line")
            val certificate = decode(Base64Compat.decode(parts[1]))
            if (parts[0] != certificate.algorithmName) throw SshException("Certificate algorithm does not match its contents")
            certificate
        }

        /** Decode a complete SSH wire-format certificate blob. */
        @JvmStatic
        @Throws(SshException::class)
        fun decode(encoded: ByteArray): SshCertificate = certificateInput("certificate") {
            val bytes = encoded.copyOf()
            val algorithm = AsciiString(ByteBufferKaitaiStream(bytes)).apply { _read() }.value()
            val baseType = certificateKeyTypes[algorithm] ?: throw SshException("Unsupported certificate algorithm: $algorithm")
            val stream = ByteBufferKaitaiStream(bytes)
            val wire = WireCertificate(stream).apply { _read() }
            if (!stream.isEof) throw SshException("Trailing bytes after certificate")
            validateOptions(wire.criticalOptions())
            validateOptions(wire.extensions())
            val raw = encodeSshString(baseType.toByteArray(Charsets.US_ASCII)) + wire.key().toByteArray()
            validateCertifiedKey(raw, baseType)
            val caStream = ByteBufferKaitaiStream(wire.signatureKey().data())
            val ca = SshPublicKey(caStream).apply { _read() }
            if (!caStream.isEof || ca.algorithmName() !in setOf("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521")) {
                throw SshException("Unsupported certificate authority key")
            }
            validateCertifiedKey(wire.signatureKey().data(), ca.algorithmName())
            SshCertificate(bytes, wire, PublicKey(baseType, raw), PublicKey(ca.algorithmName(), wire.signatureKey().data().copyOf()))
        }

        private fun validateOptions(options: WireCertificate.Options) {
            var previous: String? = null
            options.entries().forEach {
                val name = it.name().value()
                if (name.isEmpty() || name.any { c -> c.code !in 33..126 } || (previous != null && previous >= name)) {
                    throw SshException("Certificate options must have unique names in lexical order")
                }
                previous = name
            }
        }

        private fun validateCertifiedKey(bytes: ByteArray, type: String) {
            val stream = ByteBufferKaitaiStream(bytes)
            val key = SshPublicKey(stream).apply { _read() }
            if (!stream.isEof) throw SshException("Trailing bytes after certified public key")
            val valid = when (val blob = key.keyBlob()) {
                is SshEd25519PublicKeyBlob -> blob.key().data().size == 32

                is SkEd25519PublicKeyBlob -> blob.publicKey().data().size == 32

                is EcdsaPublicKeyBlob -> {
                    val curve = type.removePrefix("ecdsa-sha2-")
                    val size = when (curve) {
                        "nistp256" -> 65
                        "nistp384" -> 97
                        "nistp521" -> 133
                        else -> 0
                    }
                    blob.curveIdentifier().value() == curve && blob.q().data().size == size && blob.q().data().firstOrNull() == 4.toByte()
                }

                is SkEcdsaP256PublicKeyBlob -> blob.curveName().contentEquals("nistp256".toByteArray(Charsets.US_ASCII)) && blob.publicKey().data().size == 65 && blob.publicKey().data().firstOrNull() == 4.toByte()

                is SshRsaPublicKeyBlob -> listOf(blob.e().body(), blob.n().body()).all {
                    it.isNotEmpty() && it[0] >= 0 && it.any { b -> b != 0.toByte() } &&
                        (it.size == 1 || it[0] != 0.toByte() || it[1] < 0)
                }

                else -> false
            }
            if (!valid) throw SshException("Invalid certified public key")
        }

        private fun optionMap(options: WireCertificate.Options): Map<String, ByteArray> = Collections.unmodifiableMap(
            options.entries().associate { it.name().value() to it.data().data().copyOf() },
        )
    }
}

internal inline fun <T> certificateInput(description: String, block: () -> T): T = try {
    block()
} catch (e: SshException) {
    throw e
} catch (e: Exception) {
    throw SshException("Malformed SSH $description", e)
}
