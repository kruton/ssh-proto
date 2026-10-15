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

/** Pure ML-KEM SSH exchange; draft-harrison-sshm-mlkem-02 section 3. */
internal class MlKemKeyExchange(
    private val parameterSet: MlKemParameterSet,
    private val provider: MlKemProvider = MlKemProviderFactory.forParameterSet(parameterSet),
) : KexAlgorithm {
    override val hashAlgorithm: String = if (parameterSet == MlKemParameterSet.ML_KEM_1024) "SHA-384" else "SHA-256"
    private var privateKey: ByteArray? = null

    override fun generateClientKeys(): ByteArray {
        zeroize()
        try {
            val keys = provider.generateKeyPair()
            privateKey = keys.privateKey
            // The provider owns the private-key representation (raw Kotlin or PKCS#8 JCA).
            if (keys.publicKey.size != parameterSet.publicKeySize || keys.privateKey.isEmpty()) {
                throw SshException("Invalid $parameterSet key pair size")
            }
            return keys.publicKey
        } catch (e: Exception) {
            zeroize()
            if (e is SshException) throw e
            throw SshException("ML-KEM key generation failed", e)
        }
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): ByteArray {
        val key = privateKey ?: throw SshException("Client keys not generated")
        if (serverPublicKey.size != parameterSet.ciphertextSize) throw SshException("Invalid $parameterSet ciphertext size")
        try {
            val secret = provider.decapsulate(key, serverPublicKey)
            return try {
                if (secret.size != 32) throw SshException("Invalid ML-KEM shared secret size")
                // Section 3 and CycloneSSH use string K_PQ, preserving all 32 octets.
                // The per-method subsections' mpint wording contradicts that definition.
                encodeSshString(secret)
            } finally {
                secret.fill(0)
            }
        } catch (e: Exception) {
            if (e is SshException) throw e
            throw SshException("ML-KEM decapsulation failed", e)
        }
    }

    override fun zeroize() {
        privateKey?.fill(0)
        privateKey = null
    }
}
