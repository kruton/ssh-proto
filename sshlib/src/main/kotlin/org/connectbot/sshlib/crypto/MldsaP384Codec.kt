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
import org.connectbot.sshlib.protocol.Mpint
import org.connectbot.sshlib.protocol.SshMldsaP384PublicKeyBlob
import org.connectbot.sshlib.protocol.SshMldsaP384SignatureBlob
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import org.connectbot.sshlib.protocol.toByteArray
import java.math.BigInteger
import java.security.GeneralSecurityException

/** SSH wraps Q in a string and r/s in mpints; JCA uses raw Q and DER ECDSA. */
internal object MldsaP384Codec {
    private val parameter = MldsaAlgorithm.MLDSA87_P384
    private val order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)

    private fun scalar(bytes: ByteArray): BigInteger? {
        if (bytes.isEmpty() || bytes.size > 49) return null
        val value = BigInteger(bytes)
        return value.takeIf { it.signum() > 0 && it < order && it.toByteArray().contentEquals(bytes) }
    }

    fun verify(key: SshPublicKey, signature: SshSignature, data: ByteArray): Boolean {
        val pub = key.keyBlob() as? SshMldsaP384PublicKeyBlob ?: return false
        val body = (signature.signatureBlob() as? SshMldsaP384SignatureBlob)?.signature() ?: return false
        if (!body._io().isEof || pub.q()[0] != 4.toByte()) return false
        val r = scalar(body.r().body()) ?: return false
        val s = scalar(body.s().body()) ?: return false
        val raw = body.mldsaSignature() + EcdsaSignatureAlgorithm.encodeDerEcdsaSignature(r, s)
        val verifier = parameter.verifier(pub.mldsaKey() + pub.q())
        return try {
            verifier.update(data)
            verifier.verify(raw)
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    fun encodePublicKey(raw: ByteArray): ByteArray {
        if (raw.size != 2689 || raw[2592] != 4.toByte()) throw SshException("Invalid ML-DSA-87/P-384 public key")
        val body = SshMldsaP384PublicKeyBlob().apply {
            setLenKey(2693)
            setMldsaKey(raw.copyOfRange(0, 2592))
            setLenQ(97)
            setQ(raw.copyOfRange(2592, raw.size))
            _check()
        }
        return SshPublicKey().apply {
            setAlgorithmNameLen(parameter.sshName.length.toLong())
            setAlgorithmName(parameter.sshName)
            setKeyBlob(body)
        }.toByteArray()
    }

    fun encodeSignature(raw: ByteArray): ByteArray {
        if (raw.size !in 4635..4731) throw SshException("Invalid ML-DSA-87/P-384 signature size")
        val reader = DerReader(raw.copyOfRange(4627, raw.size))
        val (r, s) = reader.readSequence { it.readInteger() to it.readInteger() }
        reader.ensureFullyConsumed()
        if (scalar(r.toByteArray()) == null || scalar(s.toByteArray()) == null) throw SshException("Invalid P-384 signature scalar")
        val body = SshMldsaP384SignatureBlob()
        val composite = SshMldsaP384SignatureBlob.CompositeSignature(null, body, body).apply {
            setMldsaSignature(raw.copyOfRange(0, 4627))
            setR(
                Mpint().apply {
                    setLenBody(r.toByteArray().size.toLong())
                    setBody(r.toByteArray())
                    _check()
                },
            )
            setS(
                Mpint().apply {
                    setLenBody(s.toByteArray().size.toLong())
                    setBody(s.toByteArray())
                    _check()
                },
            )
        }
        body.apply {
            setLenSignature(composite.toByteArray().size.toLong())
            setSignature(composite)
            _check()
        }
        return SshSignature().apply {
            setAlgorithmNameLen(parameter.sshName.length.toLong())
            setAlgorithmName(parameter.sshName)
            setSignatureBlob(body)
        }.toByteArray()
    }
}
