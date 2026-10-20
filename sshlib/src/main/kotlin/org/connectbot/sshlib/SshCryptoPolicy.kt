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

package org.connectbot.sshlib

import io.kaitai.struct.ByteBufferKaitaiStream
import org.connectbot.sshlib.crypto.CipherEntry
import org.connectbot.sshlib.crypto.KexEntry
import org.connectbot.sshlib.crypto.MacEntry
import org.connectbot.sshlib.crypto.MldsaAlgorithm
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.crypto.certificateAlgorithm
import org.connectbot.sshlib.crypto.certificateSignatureAlgorithm
import org.connectbot.sshlib.protocol.AsciiString
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshRsaPublicKeyBlob
import org.connectbot.sshlib.protocol.SshSignature
import java.math.BigInteger

/** Stable policy names; definitions may evolve with library releases. FIPS is an algorithm filter, not a validation claim. */
enum class CryptoPolicyPreset { DEFAULT, FUTURE, FIPS, LEGACY }

/** Independently configurable algorithm lists. */
enum class AlgorithmCategory { KEX, CIPHER, MAC, HOST_KEY, PUBKEY }

/** An implemented algorithm and its availability with the current providers. */
data class SshAlgorithm(val name: String, val available: Boolean, val defaultEnabled: Boolean)

/** Why an explicit custom entry could not be used. */
enum class AlgorithmPolicyWarningReason { UNSUPPORTED, UNAVAILABLE, DH_TOO_SMALL, RSA_TOO_SMALL }

/** Structured resolution or authentication diagnostic, suitable for localization by callers. */
data class AlgorithmPolicyWarning(val category: AlgorithmCategory, val algorithm: String, val reason: AlgorithmPolicyWarningReason)

/**
 * Resolved connection policy. Obtain a fresh snapshot with [resolve] after installing crypto providers.
 * Expressions contain bare names (an exact list), or individually prefixed ^ / + / - entries.
 * Custom overrides always use DEFAULT as their base. Protocol KEX markers are managed separately.
 *
 * Preset definitions evolve with library releases:
 * - [CryptoPolicyPreset.DEFAULT]: modern algorithms, with RSA and finite-field DH minimum 2048 bits.
 * - [CryptoPolicyPreset.FUTURE]: hybrid post-quantum KEX only, 256-bit encryption keys, and RSA/DH minimum 3072 bits.
 * - [CryptoPolicyPreset.FIPS]: an AES/SHA-2/NIST ECDH/fixed-DH/RSA-SHA2/ECDSA subset. This is an algorithm filter,
 *   not a claim of FIPS validation for the provider or application.
 * - [CryptoPolicyPreset.LEGACY]: modern preferences followed by compatibility algorithms, with RSA/DH minimum 1024 bits.
 *
 * An exact expression is an ordered comma-separated list of names. Delta entries individually use `^` (prepend),
 * `+` (append), or `-` (exclude), for example `^curve25519-sha256,+diffie-hellman-group1-sha1,-ecdh-sha2-nistp256`.
 * Unsupported or unavailable positive entries are skipped and reported in [warnings]; callers should preserve the
 * original expression. [minimumRsaBits] and [minimumDhBits] are independent numeric requirements that explicit
 * algorithm selections cannot bypass. The group1 example therefore also requires `minimumDhBits = 1024`.
 *
 * Install platform crypto providers before resolving and apply the snapshot with [SshClientConfig.Builder.cryptoPolicy].
 * Persist user expressions and preset names, rather than the runtime [catalog] or resolved algorithm lists.
 * Public-key authentication selections are independent of server host-key selections.
 */
class SshCryptoPolicy private constructor(
    val preset: CryptoPolicyPreset,
    val algorithms: Map<AlgorithmCategory, List<String>>,
    val minimumRsaBits: Int,
    val minimumDhBits: Int,
    val warnings: List<AlgorithmPolicyWarning>,
) {
    internal fun acceptsKey(blob: ByteArray, category: AlgorithmCategory): Boolean = try {
        val type = AsciiString(ByteBufferKaitaiStream(blob)).apply { _read() }.value()
        if (type.endsWith("-cert-v01@openssh.com")) {
            val cert = SshCertificate.decode(blob)
            val signature = SshSignature(ByteBufferKaitaiStream(cert.signature)).apply { _read() }
            val authorityAlgorithm = signature.algorithmName()
            val allowed = algorithms.getValue(category).map(::certificateSignatureAlgorithm)
            authorityAlgorithm in allowed && acceptsKey(cert.publicKey.encoded, category) && acceptsKey(cert.signatureKey.encoded, category)
        } else {
            val key = SshPublicKey(ByteBufferKaitaiStream(blob)).apply { _read() }
            val rsa = key.keyBlob() as? SshRsaPublicKeyBlob
            rsa == null || BigInteger(1, rsa.n().body()).bitLength() >= minimumRsaBits
        }
    } catch (_: Exception) {
        false
    }

    companion object {
        /** Current implemented algorithms, including opt-in and currently unavailable entries. Never cached across provider changes. */
        @JvmStatic
        fun catalog(): Map<AlgorithmCategory, List<SshAlgorithm>> {
            val signatureDefaults = SignatureEntry.defaults.toSet()
            val signatures = SignatureEntry.entries.map { entry ->
                SshAlgorithm(entry.sshName, signatureAvailable(entry), entry in signatureDefaults)
            }
            val hostKeys = signatures.flatMap { entry ->
                listOfNotNull(entry, certificateAlgorithm(entry.name)?.let { entry.copy(name = it, defaultEnabled = false) })
            }
            val pubkeys = hostKeys.map { entry ->
                entry.copy(defaultEnabled = entry.defaultEnabled || (certificateAlgorithm(certificateSignatureAlgorithm(entry.name)) == entry.name && signatures.any { it.name == certificateSignatureAlgorithm(entry.name) && it.defaultEnabled }))
            } + listOf("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com").map { SshAlgorithm(it, true, true) }
            return mapOf(
                AlgorithmCategory.KEX to KexEntry.entries.map { SshAlgorithm(it.sshName, true, it in KexEntry.defaults) },
                AlgorithmCategory.CIPHER to CipherEntry.entries.map { SshAlgorithm(it.sshName, cipherAvailable(it), it in CipherEntry.defaults) },
                AlgorithmCategory.MAC to MacEntry.entries.map { SshAlgorithm(it.sshName, macAvailable(it), it in MacEntry.defaults) },
                AlgorithmCategory.HOST_KEY to hostKeys,
                AlgorithmCategory.PUBKEY to pubkeys,
            )
        }

        /** Check expression syntax without checking availability. Unknown names are intentionally accepted. */
        @JvmStatic
        @Throws(SshException::class)
        fun validateExpression(expression: String?) {
            parse(expression)
        }

        private fun signatureAvailable(entry: SignatureEntry): Boolean = try {
            val mldsa = MldsaAlgorithm.fromSshName(entry.sshName)
            if (mldsa != null) {
                mldsa.isAvailable()
            } else {
                val (signature, keyFactory) = when {
                    entry.sshName == "ssh-ed25519" -> "Ed25519" to "Ed25519"
                    entry.sshName == "ssh-ed448" -> "Ed448" to "Ed448"
                    entry.sshName.endsWith("nistp256") -> "SHA256withECDSA" to "EC"
                    entry.sshName.endsWith("nistp384") -> "SHA384withECDSA" to "EC"
                    entry.sshName.endsWith("nistp521") -> "SHA512withECDSA" to "EC"
                    entry.sshName == "rsa-sha2-512" -> "SHA512withRSA" to "RSA"
                    entry.sshName == "rsa-sha2-256" -> "SHA256withRSA" to "RSA"
                    else -> "SHA1withRSA" to "RSA"
                }
                java.security.Signature.getInstance(signature)
                java.security.KeyFactory.getInstance(keyFactory)
                true
            }
        } catch (_: java.security.GeneralSecurityException) {
            false
        }

        private fun cipherAvailable(entry: CipherEntry): Boolean = try {
            when (val instance = entry.create(ByteArray(entry.keyLength), ByteArray(entry.ivLength), true)) {
                is org.connectbot.sshlib.crypto.EncryptionInstance.Cipher -> instance.cipher.destroy()
                is org.connectbot.sshlib.crypto.EncryptionInstance.Aead -> instance.aead.destroy()
            }
            true
        } catch (_: java.security.GeneralSecurityException) {
            false
        }

        private fun macAvailable(entry: MacEntry): Boolean = try {
            entry.create(ByteArray(entry.keyLength)).destroy()
            true
        } catch (_: java.security.GeneralSecurityException) {
            false
        }

        private fun parse(expression: String?): List<Pair<Char, String>> {
            if (expression.isNullOrBlank()) return emptyList()
            val result = expression.split(',').map { token ->
                val value = token.trim()
                val operation = value.firstOrNull()?.takeIf { it in "^+-" } ?: '='
                val name = if (operation == '=') value else value.drop(1)
                if (name.isEmpty() || name.length > 64 || name.any { it.code !in 33..126 || it in ",*?!^+" } || name.first() == '-') {
                    throw SshException("Invalid SSH algorithm name: $name")
                }
                operation to name
            }
            if (result.map { it.second }.distinct().size != result.size) throw SshException("Duplicate or conflicting algorithm entries")
            if (result.any { it.first == '=' } && result.any { it.first != '=' }) throw SshException("Cannot mix exact and delta algorithm entries")
            return result
        }

        /**
         * Resolve a preset or DEFAULT plus custom expressions. Unsupported positive entries are preserved by the caller and skipped here.
         * Size overrides are for Custom and must not be supplied with a non-DEFAULT preset.
         */
        @JvmStatic
        @JvmOverloads
        @Throws(SshException::class)
        fun resolve(
            preset: CryptoPolicyPreset = CryptoPolicyPreset.DEFAULT,
            overrides: Map<AlgorithmCategory, String> = emptyMap(),
            minimumRsaBits: Int? = null,
            minimumDhBits: Int? = null,
        ): SshCryptoPolicy {
            if (preset != CryptoPolicyPreset.DEFAULT && (overrides.isNotEmpty() || minimumRsaBits != null || minimumDhBits != null)) throw SshException("Custom policies must inherit DEFAULT")
            val minimum = when (preset) {
                CryptoPolicyPreset.LEGACY -> 1024
                CryptoPolicyPreset.FUTURE -> 3072
                else -> 2048
            }
            val rsa = minimumRsaBits ?: minimum
            val dh = minimumDhBits ?: minimum
            if (rsa < 1024 || dh !in 1024..8192) throw SshException("RSA minimum must be at least 1024; DH minimum must be between 1024 and 8192")
            val warnings = mutableListOf<AlgorithmPolicyWarning>()
            val resolved = catalog().mapValues { (category, catalog) ->
                val defaults = catalog.filter { entry ->
                    when (preset) {
                        CryptoPolicyPreset.DEFAULT -> entry.defaultEnabled

                        CryptoPolicyPreset.LEGACY -> entry.defaultEnabled || when (category) {
                            AlgorithmCategory.KEX -> KexEntry.fromSshName(entry.name)?.hashAlgorithm == "SHA-1"
                            AlgorithmCategory.CIPHER, AlgorithmCategory.MAC -> true
                            else -> entry.name == "ssh-rsa" || entry.name == "ssh-rsa-cert-v01@openssh.com"
                        }

                        CryptoPolicyPreset.FUTURE -> when (category) {
                            AlgorithmCategory.KEX -> KexEntry.fromSshName(entry.name)?.let { it.isHybrid && it in KexEntry.defaults } == true
                            AlgorithmCategory.CIPHER -> entry.defaultEnabled && (CipherEntry.fromSshName(entry.name)?.keyLength ?: 0) >= 32
                            else -> entry.defaultEnabled
                        }

                        CryptoPolicyPreset.FIPS -> when (category) {
                            AlgorithmCategory.KEX -> entry.name.startsWith("ecdh-sha2-nistp") || entry.name in listOf("diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512")
                            AlgorithmCategory.CIPHER -> entry.defaultEnabled && entry.name.startsWith("aes")
                            AlgorithmCategory.MAC -> entry.defaultEnabled
                            else -> entry.defaultEnabled && (entry.name.startsWith("rsa-sha2-") || entry.name.startsWith("ecdsa-sha2-nistp"))
                        }
                    }
                }.sortedBy { !it.defaultEnabled }.map { it.name }
                val entries = parse(overrides[category])
                val requested = when {
                    entries.isEmpty() -> defaults

                    entries.first().first == '=' -> entries.map { it.second }

                    else -> entries.filter { it.first == '^' }.map { it.second } +
                        defaults.filter { name -> entries.none { it.second == name } } +
                        entries.filter { it.first == '+' }.map { it.second }
                }
                requested.filter { name ->
                    val entry = catalog.firstOrNull { it.name == name }
                    val reason = when {
                        entry == null -> AlgorithmPolicyWarningReason.UNSUPPORTED
                        !entry.available -> AlgorithmPolicyWarningReason.UNAVAILABLE
                        category == AlgorithmCategory.KEX && fixedDhBits(name)?.let { it < dh } == true -> AlgorithmPolicyWarningReason.DH_TOO_SMALL
                        else -> null
                    }
                    if (reason != null && entries.any { it.second == name }) warnings.add(AlgorithmPolicyWarning(category, name, reason))
                    reason == null
                }
            }
            return SshCryptoPolicy(preset, java.util.Collections.unmodifiableMap(resolved.mapValues { java.util.Collections.unmodifiableList(it.value.toList()) }), rsa, dh, java.util.Collections.unmodifiableList(warnings.toList()))
        }

        internal fun fixedDhBits(name: String): Int? = when {
            name.startsWith("diffie-hellman-group1-") -> 1024
            name.startsWith("diffie-hellman-group14-") -> 2048
            name.startsWith("diffie-hellman-group16-") -> 4096
            name.startsWith("diffie-hellman-group18-") -> 8192
            else -> null
        }
    }
}
