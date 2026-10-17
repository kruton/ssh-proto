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

package org.connectbot.sshlib.client

import org.connectbot.sshlib.crypto.EcdsaSignatureAlgorithm
import org.connectbot.sshlib.crypto.RawKeyFactory
import org.connectbot.sshlib.protocol.SshAgentcAddIdentity
import org.connectbot.sshlib.protocol.toPositiveBigInteger
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyPair
import java.security.spec.DSAPrivateKeySpec
import java.security.spec.DSAPublicKeySpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec

/** Decode only after Kaitai has validated the complete agent payload. */
internal fun decodeAgentIdentity(request: SshAgentcAddIdentity): KeyPair = when (val key = request.key()) {
    is SshAgentcAddIdentity.Rsa -> {
        val n = key.n().toPositiveBigInteger()
        val e = key.e().toPositiveBigInteger()
        val d = key.d().toPositiveBigInteger()
        val p = key.p().toPositiveBigInteger()
        val q = key.q().toPositiveBigInteger()
        require(p > BigInteger.ONE && q > BigInteger.ONE && p * q == n)
        RawKeyFactory.generateKeyPair(
            "RSA",
            RSAPublicKeySpec(n, e),
            RSAPrivateCrtKeySpec(n, e, d, p, q, d.mod(p - BigInteger.ONE), d.mod(q - BigInteger.ONE), key.iqmp().toPositiveBigInteger()),
        )
    }

    is SshAgentcAddIdentity.Dsa -> {
        val p = key.p().toPositiveBigInteger()
        val q = key.q().toPositiveBigInteger()
        val g = key.g().toPositiveBigInteger()
        RawKeyFactory.generateKeyPair("DSA", DSAPublicKeySpec(key.y().toPositiveBigInteger(), p, q, g), DSAPrivateKeySpec(key.x().toPositiveBigInteger(), p, q, g))
    }

    is SshAgentcAddIdentity.Ec -> {
        val curve = key.curve().value()
        require(request.keyType().value() == "ecdsa-sha2-$curve")
        val jcaCurve = when (curve) {
            "nistp256" -> "secp256r1"
            "nistp384" -> "secp384r1"
            "nistp521" -> "secp521r1"
            else -> error("Unsupported agent curve")
        }
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec(jcaCurve)) }
            .getParameterSpec(ECParameterSpec::class.java)
        val point = EcdsaSignatureAlgorithm.decodeEcPoint(key.point().data(), parameters)
        RawKeyFactory.generateKeyPair("EC", ECPublicKeySpec(point, parameters), ECPrivateKeySpec(key.scalar().toPositiveBigInteger(), parameters))
    }

    else -> error("Unsupported agent key type")
}
