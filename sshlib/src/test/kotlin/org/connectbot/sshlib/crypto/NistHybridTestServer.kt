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

import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

internal data class NistHybridServerExchange(val reply: ByteArray, val sharedSecret: ByteArray)

/** Independent RFC 10042 server combiner: BC ML-KEM and direct JCA ECDH, no client KEX code. */
internal object NistHybridTestServer {
    fun reply(clientInit: ByteArray, nist384: Boolean): NistHybridServerExchange {
        val fieldSize = if (nist384) 48 else 32
        val pqSize = if (nist384) 1568 else 1184
        val curve = if (nist384) "secp384r1" else "secp256r1"
        val hash = if (nist384) "SHA-384" else "SHA-256"
        val kem = if (nist384) MLKEMParameters.ml_kem_1024 else MLKEMParameters.ml_kem_768
        check(clientInit.size == pqSize + 1 + 2 * fieldSize)
        check(clientInit[pqSize] == 4.toByte())
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec(curve))
        val server = generator.generateKeyPair()
        val pub = server.public as ECPublicKey
        val clientPoint = ECPoint(
            BigInteger(1, clientInit, pqSize + 1, fieldSize),
            BigInteger(1, clientInit, pqSize + 1 + fieldSize, fieldSize),
        )
        val clientKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(clientPoint, pub.params))
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(server.private)
        agreement.doPhase(clientKey, true)
        val classical = agreement.generateSecret()
        val encapsulated = MLKEMGenerator(SecureRandom()).generateEncapsulated(
            MLKEMPublicKeyParameters(kem, clientInit.copyOfRange(0, pqSize)),
        )
        try {
            val publicKey = byteArrayOf(4) + coordinate(pub.w.affineX, fieldSize) + coordinate(pub.w.affineY, fieldSize)
            val digest = MessageDigest.getInstance(hash).digest(encapsulated.secret + classical)
            return NistHybridServerExchange(
                encapsulated.encapsulation + publicKey,
                ByteBuffer.allocate(4).putInt(digest.size).array() + digest,
            )
        } finally {
            classical.fill(0)
            encapsulated.destroy()
        }
    }

    private fun coordinate(value: BigInteger, width: Int): ByteArray {
        val raw = value.toByteArray()
        val result = ByteArray(width)
        val count = minOf(raw.size, width)
        System.arraycopy(raw, raw.size - count, result, width - count, count)
        return result
    }
}
