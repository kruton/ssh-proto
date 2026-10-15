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

package org.connectbot.sshlib.crypto.sntrup

import org.connectbot.sshlib.SshException
import java.security.SecureRandom

/** Internal boundary around the package-private, vendored BC implementation. */
internal class Sntrup761KeyPair private constructor(
    val publicKey: ByteArray,
    private var privateKey: SNTRUPrimePrivateKeyParameters?,
) {
    fun decapsulate(ciphertext: ByteArray): ByteArray {
        val key = privateKey ?: throw SshException("SNTRUP761 private key has been cleared")
        if (ciphertext.size != 1039) throw SshException("Invalid SNTRUP761 ciphertext length: ${ciphertext.size}")
        return try {
            SNTRUPrimeKEMExtractor(key).extractSecret(ciphertext)
        } catch (e: Exception) {
            throw SshException("SNTRUP761 decapsulation failed", e)
        }
    }

    fun clear() {
        privateKey?.clear()
        privateKey = null
    }

    companion object {
        fun generate(random: SecureRandom = SecureRandom()): Sntrup761KeyPair = try {
            val generator = SNTRUPrimeKeyPairGenerator()
            generator.init(SNTRUPrimeKeyGenerationParameters(random, SNTRUPrimeParameters.sntrup761))
            val pair = generator.generateKeyPair()
            Sntrup761KeyPair(
                (pair.getPublic() as SNTRUPrimePublicKeyParameters).encoded,
                pair.getPrivate() as SNTRUPrimePrivateKeyParameters,
            )
        } catch (e: Exception) {
            throw SshException("SNTRUP761 key generation failed", e)
        }
    }
}
