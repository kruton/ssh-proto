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
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.SshKeys
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.protocol.OpensshMldsaEd25519PrivateKey
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.ResourceLock
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@ResourceLock("JCA_PROVIDERS")
internal class MldsaKeyEncodingTest {
    private val message = "ML-DSA imported key test".toByteArray()

    private fun assertUsable(original: KeyPair, imported: KeyPair) {
        val expected = SshSigning.encodePublicKey(original)
        val actual = SshSigning.encodePublicKey(imported)
        assertEquals(expected.algorithmName, actual.algorithmName)
        assertContentEquals(expected.publicKeyBlob, actual.publicKeyBlob)
        val signature = SshSigning.signWithKeyPair(actual.algorithmName, imported, message)
        assertTrue(SignatureVerifier.verify(expected.publicKeyBlob, signature, message, expected.algorithmName))
    }

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `PKCS8 PEM preserves public and private keys with optional encryption`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        for (password in listOf(null, "test passphrase")) {
            val pem = SshKeys.encodePemPrivateKey(pair, password)
            assertEquals(password != null, PrivateKeyReader.isEncrypted(pem))
            assertUsable(pair, SshKeys.decodePemPrivateKey(pem, password))
            if (password == null) {
                val der = Base64Compat.decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString(""))
                assertFailsWith<SshException> { MldsaPrivateKeys.readPem(der + 0, null) }
                if (parameter != MldsaAlgorithm.MLDSA44_ED25519) {
                    val reference = BouncyCastleProvider()
                    val privateKey = KeyFactory.getInstance(parameter.jcaName, reference).generatePrivate(PKCS8EncodedKeySpec(der))
                    val signer = Signature.getInstance(parameter.jcaName, reference)
                    signer.initSign(privateKey)
                    signer.update(message)
                    val verifier = parameter.verifier(MldsaAlgorithm.decodePublicKey(pair.public).second)
                    verifier.update(message)
                    assertTrue(verifier.verify(signer.sign()))
                }
            }
            if (password != null) {
                assertFailsWith<SshException> { SshKeys.decodePemPrivateKey(pem, "wrong passphrase") }
            }
        }
    }

    @ParameterizedTest
    @EnumSource(MldsaAlgorithm::class)
    fun `provider PKCS8 imports with a companion SPKI public key`(parameter: MldsaAlgorithm) = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        val privatePem = pem("PRIVATE KEY", pair.private.encoded)
        val publicPem = pem("PUBLIC KEY", pair.public.encoded)
        assertUsable(pair, SshKeys.decodePemPrivateKey(privatePem + publicPem))
        assertFailsWith<SshException> { SshKeys.decodePemPrivateKey(privatePem) }
        val other = KeyPairGenerator.getInstance(parameter.jcaName, provider).generateKeyPair()
        assertFailsWith<SshException> { SshKeys.decodePemPrivateKey(privatePem + pem("PUBLIC KEY", other.public.encoded)) }
        val inconsistent = KeyPair(other.public, pair.private)
        assertFailsWith<SshException> { SshKeys.encodePemPrivateKey(inconsistent) }
        Unit
    }

    @Test
    fun `composite OpenSSH keys preserve seeds with optional bcrypt encryption`() = withMldsaTestProvider { provider ->
        val pair = KeyPairGenerator.getInstance("MLDSA44-Ed25519-SHA512", provider).generateKeyPair()
        for (password in listOf(null, "test passphrase")) {
            val encoded = SshKeys.encodeOpenSshPrivateKey(pair, password)
            assertEquals(password != null, PrivateKeyReader.isEncrypted(encoded))
            assertUsable(pair, SshKeys.decodePemPrivateKey(encoded, password))
            if (password != null) assertFailsWith<SshException> { SshKeys.decodePemPrivateKey(encoded, "wrong passphrase") }
        }
        val other = KeyPairGenerator.getInstance("MLDSA44-Ed25519-SHA512", provider).generateKeyPair()
        assertFailsWith<SshException> { SshKeys.encodeOpenSshPrivateKey(KeyPair(other.public, pair.private)) }
        // The SSH ML-DSA draft does not define an OpenSSH private-key container for pure ML-DSA.
        val pure = KeyPairGenerator.getInstance("ML-DSA-44", provider).generateKeyPair()
        assertFailsWith<SshException> { SshKeys.encodeOpenSshPrivateKey(pure) }
        Unit
    }

    @Test
    fun `OpenSSH schema rejects malformed public and seed lengths`() {
        // The generated schema rejects lengths before reading or allocating the payload.
        for (length in listOf(0, 1343, 1345, Int.MAX_VALUE)) {
            assertFailsWith<RuntimeException> {
                val fields = OpensshMldsaEd25519PrivateKey(ByteBufferKaitaiStream(encodeUint32(length)))
                fields._read()
            }
        }
        for (length in listOf(0, 63, 65, Int.MAX_VALUE)) {
            assertFailsWith<RuntimeException> {
                val fields = OpensshMldsaEd25519PrivateKey(
                    ByteBufferKaitaiStream(encodeSshString(ByteArray(1344)) + encodeUint32(length)),
                )
                fields._read()
            }
        }
    }

    private fun pem(label: String, data: ByteArray): String = "-----BEGIN $label-----\n" + Base64.getEncoder().encodeToString(data).chunked(64).joinToString("\n") +
        "\n-----END $label-----\n"

    private fun encodeUint32(value: Int): ByteArray = ByteBuffer.allocate(4).putInt(value).array()
}
