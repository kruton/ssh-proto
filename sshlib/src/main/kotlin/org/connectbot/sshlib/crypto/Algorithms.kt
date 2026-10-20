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

package org.connectbot.sshlib.crypto

import org.connectbot.sshlib.SshException
import java.security.Provider
import java.security.Security

private const val HASH_SHA256 = "SHA-256"
private const val HASH_SHA512 = "SHA-512"
private const val KEY_TYPE_SSH_RSA = "ssh-rsa"

internal sealed interface EncryptionInstance {
    data class Cipher(val cipher: PacketCipher) : EncryptionInstance
    data class Aead(val aead: PacketAead) : EncryptionInstance
}

internal enum class CipherEntry(
    val sshName: String,
    val keyLength: Int,
    val ivLength: Int,
    val blockSize: Int,
    val isAead: Boolean,
    private val factory: (key: ByteArray, iv: ByteArray, forEncryption: Boolean) -> EncryptionInstance,
) {
    CHACHA20_POLY1305(
        "chacha20-poly1305@openssh.com",
        64,
        0,
        8,
        true,
        { key, _, _ -> EncryptionInstance.Aead(ChaCha20Poly1305Cipher(key)) },
    ),
    AES128_GCM(
        "aes128-gcm@openssh.com",
        16,
        12,
        16,
        true,
        { key, iv, _ -> EncryptionInstance.Aead(AesGcmCipher(key, iv)) },
    ),
    AES256_GCM(
        "aes256-gcm@openssh.com",
        32,
        12,
        16,
        true,
        { key, iv, _ -> EncryptionInstance.Aead(AesGcmCipher(key, iv)) },
    ),
    AES128_CTR(
        "aes128-ctr",
        16,
        16,
        16,
        false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCtrCipher(key, iv, enc)) },
    ),
    AES256_CTR(
        "aes256-ctr",
        32,
        16,
        16,
        false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCtrCipher(key, iv, enc)) },
    ),
    AES128_CBC(
        "aes128-cbc",
        16,
        16,
        16,
        false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCbcCipher(key, iv, enc)) },
    ),
    AES256_CBC(
        "aes256-cbc",
        32,
        16,
        16,
        false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCbcCipher(key, iv, enc)) },
    ),
    TRIPLE_DES_CBC(
        "3des-cbc",
        24,
        8,
        8,
        false,
        { key, iv, enc -> EncryptionInstance.Cipher(TripleDesCbcCipher(key, iv, enc)) },
    ),
    ;

    internal fun create(key: ByteArray, iv: ByteArray, forEncryption: Boolean): EncryptionInstance = factory(key, iv, forEncryption)

    companion object {
        val defaults: List<CipherEntry> = listOf(
            CHACHA20_POLY1305,
            AES128_GCM,
            AES256_GCM,
            AES128_CTR,
            AES256_CTR,
        )

        val defaultString: String = defaults.joinToString(",") { it.sshName }

        fun fromSshName(name: String): CipherEntry? = entries.firstOrNull { it.sshName == name }
    }
}

internal enum class MacEntry(
    val sshName: String,
    val keyLength: Int,
    val macLength: Int,
    val isEtm: Boolean,
    private val factory: (key: ByteArray) -> PacketMac,
) {
    HMAC_SHA2_256_ETM(
        "hmac-sha2-256-etm@openssh.com",
        32,
        32,
        true,
        { key -> HmacSha256(key.copyOf(32)) },
    ),
    HMAC_SHA2_512_ETM(
        "hmac-sha2-512-etm@openssh.com",
        64,
        64,
        true,
        { key -> HmacSha512(key.copyOf(64)) },
    ),
    HMAC_SHA2_256(
        "hmac-sha2-256",
        32,
        32,
        false,
        { key -> HmacSha256(key.copyOf(32)) },
    ),
    HMAC_SHA2_512(
        "hmac-sha2-512",
        64,
        64,
        false,
        { key -> HmacSha512(key.copyOf(64)) },
    ),
    HMAC_SHA1_ETM(
        "hmac-sha1-etm@openssh.com",
        20,
        20,
        true,
        { key -> HmacSha1(key.copyOf(20)) },
    ),
    HMAC_SHA1(
        "hmac-sha1",
        20,
        20,
        false,
        { key -> HmacSha1(key.copyOf(20)) },
    ),
    ;

    internal fun create(key: ByteArray): PacketMac = factory(key)

    companion object {
        val defaults: List<MacEntry> = listOf(HMAC_SHA2_256_ETM, HMAC_SHA2_512_ETM)

        val defaultString: String = defaults.joinToString(",") { it.sshName }

        fun fromSshName(name: String): MacEntry? = entries.firstOrNull { it.sshName == name }
    }
}

internal enum class KexType { DH, ECDH, DH_GEX }

internal enum class KexEntry(
    val sshName: String,
    val hashAlgorithm: String,
    val type: KexType,
    val isPostQuantum: Boolean,
    private val factory: () -> KexAlgorithm,
    val isHybrid: Boolean = false,
) {
    MLKEM768X25519_SHA256(
        "mlkem768x25519-sha256",
        HASH_SHA256,
        KexType.ECDH,
        true,
        { MlKemHybridKeyExchange() },
        true,
    ),
    MLKEM768NISTP256_SHA256(
        "mlkem768nistp256-sha256",
        HASH_SHA256,
        KexType.ECDH,
        true,
        { MlKemNistHybridKeyExchange(MlKemNistParameters.NISTP256) },
        true,
    ),
    MLKEM1024NISTP384_SHA384(
        "mlkem1024nistp384-sha384",
        "SHA-384",
        KexType.ECDH,
        true,
        { MlKemNistHybridKeyExchange(MlKemNistParameters.NISTP384) },
        true,
    ),
    MLKEM768_SHA256("mlkem768-sha256", HASH_SHA256, KexType.ECDH, true, { MlKemKeyExchange(MlKemParameterSet.ML_KEM_768) }),
    MLKEM1024_SHA384("mlkem1024-sha384", "SHA-384", KexType.ECDH, true, { MlKemKeyExchange(MlKemParameterSet.ML_KEM_1024) }),
    SNTRUP761X25519_SHA512(
        "sntrup761x25519-sha512",
        HASH_SHA512,
        KexType.ECDH,
        true,
        { SntrupHybridKeyExchange() },
        true,
    ),
    SNTRUP761X25519_SHA512_OPENSSH(
        "sntrup761x25519-sha512@openssh.com",
        HASH_SHA512,
        KexType.ECDH,
        true,
        { SntrupHybridKeyExchange() },
        true,
    ),
    CURVE25519_SHA256(
        "curve25519-sha256",
        HASH_SHA256,
        KexType.ECDH,
        false,
        { Curve25519KeyExchange() },
    ),
    ECDH_SHA2_NISTP256(
        "ecdh-sha2-nistp256",
        HASH_SHA256,
        KexType.ECDH,
        false,
        { EcdhKeyExchange("nistp256") },
    ),
    ECDH_SHA2_NISTP384(
        "ecdh-sha2-nistp384",
        "SHA-384",
        KexType.ECDH,
        false,
        { EcdhKeyExchange("nistp384") },
    ),
    ECDH_SHA2_NISTP521(
        "ecdh-sha2-nistp521",
        HASH_SHA512,
        KexType.ECDH,
        false,
        { EcdhKeyExchange("nistp521") },
    ),
    DH_GROUP18_SHA512(
        "diffie-hellman-group18-sha512",
        HASH_SHA512,
        KexType.DH,
        false,
        { DiffieHellman(HASH_SHA512, DhGroups.GROUP18_P, DhGroups.GENERATOR) },
    ),
    DH_GROUP16_SHA512(
        "diffie-hellman-group16-sha512",
        HASH_SHA512,
        KexType.DH,
        false,
        { DiffieHellman(HASH_SHA512, DhGroups.GROUP16_P, DhGroups.GENERATOR) },
    ),
    DH_GROUP_EXCHANGE_SHA256(
        "diffie-hellman-group-exchange-sha256",
        HASH_SHA256,
        KexType.DH_GEX,
        false,
        { DiffieHellmanGroupExchange(HASH_SHA256) },
    ),
    DH_GROUP14_SHA256(
        "diffie-hellman-group14-sha256",
        HASH_SHA256,
        KexType.DH,
        false,
        { DiffieHellman(HASH_SHA256, DhGroups.GROUP14_P, DhGroups.GENERATOR) },
    ),
    DH_GROUP14_SHA1(
        "diffie-hellman-group14-sha1",
        "SHA-1",
        KexType.DH,
        false,
        { DiffieHellman("SHA-1", DhGroups.GROUP14_P, DhGroups.GENERATOR) },
    ),
    DH_GROUP_EXCHANGE_SHA1(
        "diffie-hellman-group-exchange-sha1",
        "SHA-1",
        KexType.DH_GEX,
        false,
        { DiffieHellmanGroupExchange("SHA-1") },
    ),
    DH_GROUP1_SHA1(
        "diffie-hellman-group1-sha1",
        "SHA-1",
        KexType.DH,
        false,
        { DiffieHellman("SHA-1", DhGroups.GROUP1_P, DhGroups.GENERATOR) },
    ),
    ;

    internal fun create(): KexAlgorithm = factory()

    companion object {
        val defaults: List<KexEntry> = entries.filter {
            it !in setOf(MLKEM768_SHA256, MLKEM1024_SHA384, DH_GROUP14_SHA1, DH_GROUP_EXCHANGE_SHA1, DH_GROUP1_SHA1)
        }

        val defaultString: String =
            defaults.joinToString(",") { it.sshName } + ",kex-strict-c-v00@openssh.com,ext-info-c"

        fun fromSshName(name: String): KexEntry? = entries.firstOrNull { it.sshName == name }
    }
}

internal enum class SignatureEntry(
    val sshName: String,
    internal val algorithm: SshSignatureAlgorithm,
) {
    SSH_MLDSA44_ED25519("ssh-mldsa44-ed25519", MldsaSignatureAlgorithm(MldsaAlgorithm.MLDSA44_ED25519)),
    SSH_MLDSA87_P384("ssh-mldsa87-p384", MldsaSignatureAlgorithm(MldsaAlgorithm.MLDSA87_P384)),
    SSH_MLDSA44("ssh-mldsa-44", MldsaSignatureAlgorithm(MldsaAlgorithm.MLDSA44)),
    SSH_MLDSA65("ssh-mldsa-65", MldsaSignatureAlgorithm(MldsaAlgorithm.MLDSA65)),
    SSH_MLDSA87("ssh-mldsa-87", MldsaSignatureAlgorithm(MldsaAlgorithm.MLDSA87)),
    SSH_ED25519("ssh-ed25519", Ed25519SignatureAlgorithm),
    SSH_ED448("ssh-ed448", Ed448SignatureAlgorithm),
    ECDSA_SHA2_NISTP256("ecdsa-sha2-nistp256", EcdsaSignatureAlgorithm),
    ECDSA_SHA2_NISTP384("ecdsa-sha2-nistp384", EcdsaSignatureAlgorithm),
    ECDSA_SHA2_NISTP521("ecdsa-sha2-nistp521", EcdsaSignatureAlgorithm),
    RSA_SHA2_256("rsa-sha2-256", RsaSignatureAlgorithm),
    RSA_SHA2_512("rsa-sha2-512", RsaSignatureAlgorithm),
    SSH_RSA(KEY_TYPE_SSH_RSA, RsaSignatureAlgorithm),
    ;

    companion object {
        // Resolve providers when constructing configuration, rather than freezing availability at class load.
        val defaults: List<SignatureEntry>
            get() = entries.filter {
                when (it) {
                    SSH_RSA, SSH_MLDSA44, SSH_MLDSA65, SSH_MLDSA87 -> false
                    SSH_MLDSA87_P384 -> MldsaAlgorithm.MLDSA87_P384.isAvailable()
                    SSH_MLDSA44_ED25519 -> MldsaAlgorithm.MLDSA44_ED25519.isAvailable()
                    else -> true
                }
            }

        val defaultString: String get() = defaults.joinToString(",") { it.sshName }

        fun validateHostAlgorithms(names: String, providers: List<Provider> = Security.getProviders().toList()) {
            names.split(',').mapNotNull(MldsaAlgorithm::fromSshName).forEach {
                if (!it.isAvailable(providers)) throw SshException("Host key algorithm ${it.sshName} is unavailable on this platform")
            }
        }

        fun fromSshName(name: String): SignatureEntry? = entries.firstOrNull { it.sshName == name }

        private val rsaPreferenceOrder = listOf("rsa-sha2-512", "rsa-sha2-256", KEY_TYPE_SSH_RSA)

        /**
         * Picks the best RSA signing algorithm allowed by the client's configured
         * algorithm wishlist and the server's advertised list. When RFC 8308
         * server-sig-algs is absent, only an explicitly allowed ssh-rsa is usable,
         * matching OpenSSH's base-key fallback behavior.
         */
        fun negotiateRsaAlgorithm(serverSigAlgs: Set<String>?, allowedAlgorithms: Set<String>): String? {
            if (serverSigAlgs == null) {
                return KEY_TYPE_SSH_RSA.takeIf { it in allowedAlgorithms }
            }
            return rsaPreferenceOrder.firstOrNull { it in allowedAlgorithms && it in serverSigAlgs }
        }
    }
}

internal enum class CompressionEntry(
    val sshName: String,
    val delayedActivation: Boolean,
    private val factory: () -> PacketCompressor?,
) {
    ZLIB_OPENSSH("zlib@openssh.com", delayedActivation = true, { ZlibCompressor() }),
    ZLIB("zlib", delayedActivation = false, { ZlibCompressor() }),
    NONE("none", delayedActivation = false, { null }),
    ;

    internal fun create(): PacketCompressor? = factory()

    companion object {
        val defaults: List<CompressionEntry> = listOf(NONE)

        val defaultString: String = defaults.joinToString(",") { it.sshName }

        val enabledString: String = entries.joinToString(",") { it.sshName }

        fun fromSshName(name: String): CompressionEntry? = entries.firstOrNull { it.sshName == name }
    }
}
