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
import org.connectbot.sshlib.protocol.SshMldsaPublicKeyBlob
import org.connectbot.sshlib.protocol.SshMldsaSignatureBlob
import org.connectbot.sshlib.protocol.SshPublicKey
import org.connectbot.sshlib.protocol.SshSignature
import org.connectbot.sshlib.protocol.toByteArray
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.PublicKey

internal class MldsaSignatureAlgorithm(private val parameter: MldsaAlgorithm) : SshSignatureAlgorithm {
    override fun verify(pubKey: SshPublicKey, sig: SshSignature, data: ByteArray): Boolean {
        if (pubKey.algorithmName() != parameter.sshName || sig.algorithmName() != parameter.sshName) return false
        if (parameter == MldsaAlgorithm.MLDSA87_P384) return MldsaP384Codec.verify(pubKey, sig, data)
        val key = (pubKey.keyBlob() as? SshMldsaPublicKeyBlob)?.key() ?: return false
        val signature = (sig.signatureBlob() as? SshMldsaSignatureBlob)?.signature() ?: return false
        if (key.size != parameter.publicKeySize || signature.size != parameter.maxSignatureSize) return false
        val verifier = parameter.verifier(key)
        return try {
            verifier.update(data)
            verifier.verify(signature)
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    override fun sign(algorithmName: String, privateKey: PrivateKey, data: ByteArray): ByteArray {
        if (algorithmName != parameter.sshName) throw SshException("Wrong algorithm for ${parameter.sshName}: $algorithmName")
        val signer = parameter.signer(privateKey)
        val raw = try {
            signer.update(data)
            signer.sign()
        } catch (e: GeneralSecurityException) {
            throw SshException("${parameter.sshName} signing failed", e)
        } catch (e: RuntimeException) {
            throw SshException("${parameter.sshName} signing failed", e)
        }
        if (parameter == MldsaAlgorithm.MLDSA87_P384) return MldsaP384Codec.encodeSignature(raw)
        if (raw.size != parameter.maxSignatureSize) throw SshException("Invalid ${parameter.sshName} signature size: ${raw.size}")
        val body = SshMldsaSignatureBlob(parameter.maxSignatureSize.toLong()).apply {
            setLenSignature(raw.size.toLong())
            setSignature(raw)
            _check()
        }
        return SshSignature().apply {
            setAlgorithmNameLen(parameter.sshName.length.toLong())
            setAlgorithmName(parameter.sshName)
            setSignatureBlob(body)
        }.toByteArray()
    }

    companion object {
        fun encodePublicKey(publicKey: PublicKey, keyType: String): ByteArray {
            val (parameter, raw) = MldsaAlgorithm.decodePublicKey(publicKey)
            if (parameter.sshName != keyType) throw SshException("ML-DSA key does not match $keyType")
            if (parameter == MldsaAlgorithm.MLDSA87_P384) return MldsaP384Codec.encodePublicKey(raw)
            val body = SshMldsaPublicKeyBlob(parameter.publicKeySize.toLong()).apply {
                setLenKey(raw.size.toLong())
                setKey(raw)
                _check()
            }
            return SshPublicKey().apply {
                setAlgorithmNameLen(keyType.length.toLong())
                setAlgorithmName(keyType)
                setKeyBlob(body)
            }.toByteArray()
        }
    }
}
