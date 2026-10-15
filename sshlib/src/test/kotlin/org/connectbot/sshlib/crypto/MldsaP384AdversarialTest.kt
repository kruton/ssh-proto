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
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.protocol.SshMldsaP384SignatureBlob
import org.connectbot.sshlib.protocol.SshSignature
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@ResourceLock("JCA_PROVIDERS")
internal class MldsaP384AdversarialTest {
    @Test
    fun `truncations forged lengths invalid points and noncanonical scalars cannot authenticate`() = withMldsaTestProvider { provider ->
        val parameter = MldsaAlgorithm.MLDSA87_P384
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val data = "host signature parser adversarial test".toByteArray()
        val key = SshSigning.encodePublicKey(pair).publicKeyBlob
        val signature = SshSigning.signWithKeyPair(parameter.sshName, pair, data)
        fun accepts(candidateKey: ByteArray = key, candidateSignature: ByteArray = signature): Boolean = try {
            SignatureVerifier.verify(candidateKey, candidateSignature, data, parameter.sshName)
        } catch (_: Exception) {
            false
        }
        fun changedLength(bytes: ByteArray, offset: Int, length: Int) = bytes.copyOf().also {
            ByteBuffer.wrap(it).putInt(offset, length)
        }
        assertTrue(accepts())
        for (size in key.indices) assertFalse(accepts(candidateKey = key.copyOf(size)), "key truncated to $size")
        for (size in signature.indices) assertFalse(accepts(candidateSignature = signature.copyOf(size)), "signature truncated to $size")
        for (length in listOf(0, Int.MAX_VALUE, Int.MIN_VALUE, -1)) {
            assertFalse(accepts(candidateKey = changedLength(key, 0, length)))
            assertFalse(accepts(candidateSignature = changedLength(signature, 0, length)))
        }
        val prefixSize = 4 + parameter.sshName.length
        val qLengthOffset = prefixSize + 4 + 2592
        val rLengthOffset = prefixSize + 4 + 4627
        val parsed = SshSignature(ByteBufferKaitaiStream(signature)).apply { _read() }
        val body = (parsed.signatureBlob() as SshMldsaP384SignatureBlob).signature()
        val sLengthOffset = rLengthOffset + 4 + body.r().body().size
        for (length in listOf(0, 1, 49, 50, 96, 98, 2692, 2694, 4636, 4734, Int.MAX_VALUE, Int.MIN_VALUE, -1)) {
            assertFalse(accepts(candidateKey = changedLength(key, prefixSize, length)), "key length $length")
            assertFalse(accepts(candidateKey = changedLength(key, qLengthOffset, length)), "point length $length")
            assertFalse(accepts(candidateSignature = changedLength(signature, prefixSize, length)), "signature length $length")
            for (offset in listOf(rLengthOffset, sLengthOffset)) {
                if (length != ByteBuffer.wrap(signature).getInt(offset)) {
                    assertFalse(accepts(candidateSignature = changedLength(signature, offset, length)), "scalar length $length at $offset")
                }
            }
        }
        val qOffset = qLengthOffset + 4
        for (tag in listOf(0, 2, 3, 6, 7, 255)) {
            assertFalse(accepts(candidateKey = key.copyOf().also { it[qOffset] = tag.toByte() }))
        }
        assertFalse(accepts(candidateKey = key.copyOf().also { it.fill(0, qOffset + 1, it.size) }))
        assertFalse(accepts(candidateKey = key.copyOf().also { it.fill(0xff.toByte(), qOffset + 1, it.size) }))
        val order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)
        val badScalars = listOf(byteArrayOf(), byteArrayOf(0), byteArrayOf(-1), byteArrayOf(0, 1), ByteArray(50) { 1 }, order.toByteArray(), (order + BigInteger.ONE).toByteArray())
        val prefix = encodeSshString(parameter.sshName.toByteArray(Charsets.US_ASCII))
        for (bad in badScalars) {
            for ((r, s) in listOf(bad to body.s().body(), body.r().body() to bad)) {
                val invalid = prefix + encodeSshString(body.mldsaSignature() + encodeSshString(r) + encodeSshString(s))
                assertFalse(accepts(candidateSignature = invalid))
            }
        }
        assertFalse(accepts(candidateKey = key + 0))
        assertFalse(accepts(candidateSignature = signature + 0))
        assertFalse(SignatureVerifier.verify(key, signature, data, "ssh-mldsa-87"))
        assertTrue(accepts())
    }
}
