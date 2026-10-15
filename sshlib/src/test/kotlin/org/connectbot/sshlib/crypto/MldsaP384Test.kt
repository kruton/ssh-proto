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

import io.kaitai.struct.ByteBufferKaitaiStream
import org.bouncycastle.jcajce.spec.ContextParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.protocol.SshMldsaP384SignatureBlob
import org.connectbot.sshlib.protocol.SshSignature
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@ResourceLock("JCA_PROVIDERS")
internal class MldsaP384Test {
    @Test
    fun `SSH composite verifies independently with BC ML-DSA and JCA ECDSA`() = withMldsaTestProvider { provider ->
        val parameter = MldsaAlgorithm.MLDSA87_P384
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val message = "P-384 SSH composite test".toByteArray()
        val key = SshSigning.encodePublicKey(pair)
        val signature = SshSigning.signWithKeyPair(parameter.sshName, pair, message)
        assertTrue(SignatureVerifier.verify(key.publicKeyBlob, signature, message, parameter.sshName))
        assertTrue(SignatureVerifier.verifyWithKeyType(key.publicKeyBlob, signature, message))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob, signature, message + 1, parameter.sshName))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob + 0, signature, message, parameter.sshName))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob, signature + 0, message, parameter.sshName))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob, signature, message, "ssh-mldsa-87"))
        assertFailsWith<RuntimeException> {
            SignatureVerifier.verify(key.publicKeyBlob, signature.copyOf(signature.size - 1), message, parameter.sshName)
        }
        val parsed = SshSignature(ByteBufferKaitaiStream(signature)).apply { _read() }
        val blob = (parsed.signatureBlob() as SshMldsaP384SignatureBlob).signature()
        val rawKey = MldsaAlgorithm.decodePublicKey(pair.public).second
        val label = "COMPSIG-MLDSA87-ECDSA-P384-SHA512".toByteArray()
        val representative = "CompositeAlgorithmSignatures2025".toByteArray() + label + byteArrayOf(0) + MessageDigest.getInstance("SHA-512").digest(message)
        val bc = BouncyCastleProvider()
        val mlKey = KeyFactory.getInstance("ML-DSA-87", bc).generatePublic(X509EncodedKeySpec(MldsaAlgorithm.MLDSA87.subjectPublicKeyInfo(rawKey.copyOfRange(0, 2592))))
        val mlVerifier = Signature.getInstance("ML-DSA-87", bc)
        mlVerifier.initVerify(mlKey)
        mlVerifier.setParameter(ContextParameterSpec(label))
        mlVerifier.update(representative)
        assertTrue(mlVerifier.verify(blob.mldsaSignature()))
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp384r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val q = rawKey.copyOfRange(2592, rawKey.size)
        val point = ECPoint(BigInteger(1, q.copyOfRange(1, 49)), BigInteger(1, q.copyOfRange(49, 97)))
        val ecKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
        val ecVerifier = Signature.getInstance("SHA384withECDSA")
        ecVerifier.initVerify(ecKey)
        ecVerifier.update(representative)
        assertTrue(ecVerifier.verify(EcdsaSignatureAlgorithm.encodeDerEcdsaSignature(BigInteger(blob.r().body()), BigInteger(blob.s().body()))))
        val prefix = encodeSshString(parameter.sshName.toByteArray())
        val encodedBody = blob.mldsaSignature() + encodeMpint(blob.r().body()) + encodeMpint(blob.s().body())
        for (offset in listOf(0, 4626, encodedBody.lastIndex)) {
            val damaged = encodedBody.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            assertFalse(SignatureVerifier.verify(key.publicKeyBlob, prefix + encodeSshString(damaged), message, parameter.sshName))
        }
        assertFalse(runCatching { SignatureVerifier.verify(key.publicKeyBlob, prefix + encodeSshString(encodedBody + 0), message, parameter.sshName) }.getOrDefault(false))
        for (badR in listOf(byteArrayOf(), byteArrayOf(0), byteArrayOf(-1), byteArrayOf(0, 1), ByteArray(50) { 1 })) {
            val body = blob.mldsaSignature() + encodeSshString(badR) + encodeMpint(blob.s().body())
            assertFalse(runCatching { SignatureVerifier.verify(key.publicKeyBlob, prefix + encodeSshString(body), message, parameter.sshName) }.getOrDefault(false))
        }
        assertTrue(parameter.isAvailable(listOf(provider)))
        assertTrue(parameter.sshName in SignatureEntry.defaultString)
    }
}
