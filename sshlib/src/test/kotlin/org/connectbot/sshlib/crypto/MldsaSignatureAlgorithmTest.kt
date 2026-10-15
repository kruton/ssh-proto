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
import kotlinx.coroutines.test.runTest
import org.bouncycastle.jcajce.spec.ContextParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.connectbot.sshlib.KnownHostsVerifier
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.protocol.SshMldsaSignatureBlob
import org.connectbot.sshlib.protocol.SshSignature
import org.conscrypt.Conscrypt
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.nio.file.Files
import java.security.Key
import java.security.KeyFactory
import java.security.KeyFactorySpi
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.connectbot.sshlib.PublicKey as SshHostKey

/** These providers are test dependencies only; production operations use the installed JCA registry. */
internal inline fun <T> withMldsaTestProvider(block: (Provider) -> T): T {
    val provider = Conscrypt.newProviderBuilder().setName("CbsshMldsaTest").build()
    Security.addProvider(provider)
    try {
        return block(provider)
    } finally {
        Security.removeProvider(provider.name)
    }
}

@ResourceLock("JCA_PROVIDERS")
internal class MldsaSignatureAlgorithmTest {
    private val message = "SSH ML-DSA conformance test".toByteArray()
    private val reference = BouncyCastleProvider()

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `signatures interoperate with an independent implementation`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val key = SshSigning.encodePublicKey(pair)
        assertEquals(parameter.sshName, key.algorithmName)
        val signature = SshSigning.signWithKeyPair(parameter.sshName, pair, message)
        assertTrue(SignatureVerifier.verify(key.publicKeyBlob, signature, message, parameter.sshName))
        assertTrue(SignatureVerifier.verifyWithKeyType(key.publicKeyBlob, signature, message))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob, signature, message + 1, parameter.sshName))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob + 0, signature, message, parameter.sshName))
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob, signature + 0, message, parameter.sshName))
        val parsed = SshSignature(ByteBufferKaitaiStream(signature)).apply { _read() }
        val raw = (parsed.signatureBlob() as SshMldsaSignatureBlob).signature()
        assertEquals(parameter.signatureSize, raw.size)

        if (parameter == MldsaAlgorithm.MLDSA44_ED25519) {
            val publicBytes = MldsaAlgorithm.decodePublicKey(pair.public).second
            val representative = "CompositeAlgorithmSignatures2025".toByteArray() +
                "COMPSIG-MLDSA44-Ed25519-SHA512".toByteArray() + byteArrayOf(0) +
                MessageDigest.getInstance("SHA-512").digest(message)
            val mlKey = KeyFactory.getInstance("ML-DSA-44", reference).generatePublic(
                X509EncodedKeySpec(MldsaAlgorithm.MLDSA44.subjectPublicKeyInfo(publicBytes.copyOfRange(0, 1312))),
            )
            val mlVerifier = Signature.getInstance("ML-DSA-44", reference)
            mlVerifier.initVerify(mlKey)
            mlVerifier.setParameter(ContextParameterSpec("COMPSIG-MLDSA44-Ed25519-SHA512".toByteArray()))
            mlVerifier.update(representative)
            assertTrue(mlVerifier.verify(raw.copyOfRange(0, 2420)))
            val edSpki = encodeDer {
                sequence {
                    sequence { objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70)) }
                    bitString(publicBytes.copyOfRange(1312, 1344))
                }
            }
            val edKey = KeyFactory.getInstance("Ed25519", reference).generatePublic(X509EncodedKeySpec(edSpki))
            val edVerifier = Signature.getInstance("Ed25519", reference)
            edVerifier.initVerify(edKey)
            edVerifier.update(representative)
            assertTrue(edVerifier.verify(raw.copyOfRange(2420, 2484)))
            for (offset in listOf(0, 2420)) {
                val badSignature = signature.copyOf().apply { this[size - raw.size + offset] = (this[size - raw.size + offset].toInt() xor 1).toByte() }
                assertFalse(SignatureVerifier.verify(key.publicKeyBlob, badSignature, message, parameter.sshName))
            }
        } else {
            val referenceKey = KeyFactory.getInstance(parameter.jcaName, reference).generatePublic(X509EncodedKeySpec(pair.public.encoded))
            val verifier = Signature.getInstance(parameter.jcaName, reference)
            verifier.initVerify(referenceKey)
            verifier.update(message)
            assertTrue(verifier.verify(raw))
            // Sign independently, then verify via the library (native JDK when available, Conscrypt otherwise).
            val referencePrivate = KeyFactory.getInstance(parameter.jcaName, reference).generatePrivate(
                PKCS8EncodedKeySpec(pair.private.encoded),
            )
            val signer = Signature.getInstance(parameter.jcaName, reference)
            signer.initSign(referencePrivate)
            signer.update(message)
            val referenceBlob = encodeSshString(parameter.sshName.toByteArray()) + encodeSshString(signer.sign())
            assertTrue(SignatureVerifier.verify(key.publicKeyBlob, referenceBlob, message, parameter.sshName))
        }
    }

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `known hosts accepts pinned ML-DSA keys`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        runTest {
            val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
            val key = SshSigning.encodePublicKey(pair)
            val file = Files.createTempFile("cbssh-mldsa-known-hosts", ".txt").toFile()
            try {
                file.writeText("example.test ${key.algorithmName} ${Base64.getEncoder().encodeToString(key.publicKeyBlob)}\n")
                val verifier = KnownHostsVerifier(file, "example.test")
                assertTrue(verifier.verify(SshHostKey(key.algorithmName, key.publicKeyBlob)))
                val other = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
                assertFalse(verifier.verify(SshHostKey(key.algorithmName, SshSigning.encodePublicKey(other).publicKeyBlob)))
            } finally {
                file.delete()
            }
        }
    }

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `schemas reject incorrect sizes and truncated payloads`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val key = SshSigning.encodePublicKey(pair)
        val signature = SshSigning.signWithKeyPair(parameter.sshName, pair, message)
        val prefix = encodeSshString(parameter.sshName.toByteArray())
        for (size in listOf(0, parameter.signatureSize - 1, parameter.signatureSize + 1)) {
            assertFailsWith<RuntimeException> {
                SignatureVerifier.verify(key.publicKeyBlob, prefix + encodeSshString(ByteArray(size)), message, parameter.sshName)
            }
        }
        for (size in listOf(0, parameter.publicKeySize - 1, parameter.publicKeySize + 1)) {
            assertFailsWith<RuntimeException> {
                SignatureVerifier.verify(prefix + encodeSshString(ByteArray(size)), signature, message, parameter.sshName)
            }
        }
        assertFailsWith<RuntimeException> {
            SignatureVerifier.verify(key.publicKeyBlob, signature.copyOf(signature.size - 1), message, parameter.sshName)
        }
        assertFalse(SignatureVerifier.verify(key.publicKeyBlob, signature, message, "ssh-ed25519"))
    }

    @Test
    fun `pure algorithms are opt-in and composite defaults track installed providers`() {
        val before = Security.getProviders().map { it.name }
        withMldsaTestProvider { provider ->
            assertTrue(MldsaAlgorithm.MLDSA44_ED25519.isAvailable(listOf(provider)))
            assertEquals(SignatureEntry.SSH_MLDSA44_ED25519, SignatureEntry.defaults.first())
            for (parameter in MldsaAlgorithm.entries) {
                assertFalse(parameter.isAvailable(emptyList()))
                if (parameter != MldsaAlgorithm.MLDSA44_ED25519) assertFalse(parameter.sshName in SignatureEntry.defaultString)
            }
        }
        assertEquals(before, Security.getProviders().map { it.name })
    }

    @Test
    fun `generic ML-DSA services support each pure parameter set without enabling composites`() = withMldsaTestProvider { provider ->
        val generic = object : Provider("GenericMldsa", "1.0", "Generic services only") {
            init {
                for (type in listOf("KeyFactory", "Signature")) {
                    put("$type.ML-DSA", provider.getService(type, "ML-DSA").className)
                }
            }
        }
        val providers = listOf<Provider>(generic)
        assertFalse(MldsaAlgorithm.MLDSA44_ED25519.isAvailable(providers))
        for (parameter in MldsaAlgorithm.entries.filter { it != MldsaAlgorithm.MLDSA44_ED25519 }) {
            assertTrue(parameter.isAvailable(providers))
            val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
            val raw = MldsaAlgorithm.decodePublicKey(pair.public).second
            val signer = parameter.signer(pair.private, providers)
            signer.update(message)
            val signature = signer.sign()
            assertEquals(parameter.signatureSize, signature.size)
            val verifier = parameter.verifier(raw, providers)
            verifier.update(message)
            assertTrue(verifier.verify(signature))
        }
    }

    @Test
    fun `explicit unsupported host algorithms fail without affecting classical choices`() {
        SignatureEntry.validateHostAlgorithms("ssh-ed25519,rsa-sha2-512", emptyList())
        for (parameter in MldsaAlgorithm.entries) {
            val failure = assertFailsWith<SshException> {
                SignatureEntry.validateHostAlgorithms("${parameter.sshName},ssh-ed25519", emptyList())
            }
            assertTrue(failure.message.orEmpty().contains("unavailable"))
        }
    }

    @Test
    fun `provider selection skips advertised services that reject raw keys`() = withMldsaTestProvider { provider ->
        val rejecting = RejectingMldsaProvider()
        val providers = listOf(rejecting, provider)
        for (parameter in MldsaAlgorithm.entries) {
            assertFalse(parameter.isAvailable(listOf(rejecting)))
            assertTrue(parameter.isAvailable(providers))
            val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
            val raw = MldsaAlgorithm.decodePublicKey(pair.public).second
            assertEquals(provider.name, parameter.verifier(raw, providers).provider.name)
        }
    }

    @Test
    fun `signing rejects the wrong parameter set`() = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance("ML-DSA-65", provider).generateKeyPair()
        assertFailsWith<SshException> { SshSigning.signWithKeyPair("ssh-mldsa-44", pair, message) }
        assertFailsWith<SshException> { SshPublicKeyEncoder.encode(pair, "ssh-mldsa-87") }
        Unit
    }
}

private class RejectingMldsaProvider : Provider("RejectingMldsa", 1.0, "Raw keys unavailable") {
    init {
        for (parameter in MldsaAlgorithm.entries) {
            put("KeyFactory.${parameter.jcaName}", RejectingMldsaKeyFactory::class.java.name)
        }
    }
}

class RejectingMldsaKeyFactory : KeyFactorySpi() {
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey = throw UnsupportedOperationException("Keystore keys only")
    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey = throw InvalidKeySpecException("Keystore keys only")
    override fun <T : KeySpec> engineGetKeySpec(key: Key, keySpec: Class<T>): T = throw InvalidKeySpecException("Keystore keys only")
    override fun engineTranslateKey(key: Key): Key = throw UnsupportedOperationException("Keystore keys only")
}
