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

package org.connectbot.sshlib

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.crypto.CERTIFICATE_SUFFIX
import org.connectbot.sshlib.crypto.SignatureVerifier
import org.connectbot.sshlib.protocol.createByteString
import org.connectbot.sshlib.protocol.toByteArray
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.nio.file.Path
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.connectbot.sshlib.protocol.SshCertificate as WireCertificate

class SshCertificateTest {
    @TempDir
    lateinit var directory: Path

    @ParameterizedTest
    @ValueSource(strings = ["ed25519", "rsa", "ecdsa256", "ecdsa384", "ecdsa521", "sk-ed25519", "sk-ecdsa256"])
    fun `decode user certificates and validate original CA signatures`(kind: String) {
        val certificate = certificateFixture("user-$kind")
        assertEquals(SshCertificate.Type.USER, certificate.type)
        assertEquals(listOf("certificate-access"), certificate.principals)
        assertEquals("user-$kind", certificate.keyId)
        assertEquals(certificateAuthority(), certificate.signatureKey)
        assertEquals(certificate.encoded.toList(), certificate.toAuthPublicKey().publicKeyBlob.toList())
        assertTrue(validCertificateSignature(certificate))
        assertEquals(certificate.algorithmName, SshCertificate.decode(certificate.encoded).algorithmName)
    }

    @Test
    fun `unsigned serial and unlimited validity survive decoding`() {
        assertEquals(9223372036854775825uL, certificateFixture("user-high-serial").serial)
        val forever = certificateFixture("user-forever")
        assertEquals(0uL, forever.validAfter)
        assertEquals(ULong.MAX_VALUE, forever.validBefore)
    }

    @Test
    fun `host certificates cannot be user credentials`() {
        assertFailsWith<SshException> { certificateFixture().toAuthPublicKey() }
    }

    @Test
    fun `decoder rejects malformed input and mismatching text algorithm`() {
        val certificate = certificateFixture()
        assertFailsWith<SshException> { SshCertificate.decode(certificate.encoded + byteArrayOf(0)) }
        assertFailsWith<SshException> { SshCertificate.decode(certificate.encoded.copyOf(30)) }
        val line = certificateResource("host-ed25519-cert.pub").toString(Charsets.UTF_8)
        assertFailsWith<SshException> { SshCertificate.decode(line.replaceFirst("ssh-ed25519", "ssh-rsa")) }
        assertFailsWith<SshException> { SshCertificate.decode("ssh-ed25519$CERTIFICATE_SUFFIX invalid!") }
    }

    @Test
    fun `certificate parsing rejects chains algorithm aliases and duplicate options`() {
        val user = certificateFixture("user-ed25519")
        fun wire() = WireCertificate(ByteBufferKaitaiStream(user.encoded)).apply { _read() }
        val chained = wire().apply { setSignatureKey(createByteString(certificateFixture().encoded)) }
        assertFailsWith<SshException> { SshCertificate.decode(chained.toByteArray()) }
        val duplicate = wire()
        val extensions = duplicate.extensions()
        val option = extensions.entries().first()
        val size = option.toByteArray().size
        extensions.entries().add(option)
        duplicate.setExtensionsLen(duplicate.extensionsLen() + size)
        assertFailsWith<SshException> { SshCertificate.decode(duplicate.toByteArray()) }
        val invalidAlias = wire().apply {
            setAlgorithmName(org.connectbot.sshlib.protocol.createAsciiString("rsa-sha2-512$CERTIFICATE_SUFFIX"))
        }
        assertFailsWith<SshException> { SshCertificate.decode(invalidAlias.toByteArray()) }
    }

    @Test
    fun `certified RSA integers must use canonical positive mpint encodings`() {
        val certificate = certificateFixture("host-rsa")
        val wire = WireCertificate(ByteBufferKaitaiStream(certificate.encoded)).apply { _read() }
        val key = wire.key() as org.connectbot.sshlib.protocol.SshRsaPublicKeyBlob
        val noncanonical = byteArrayOf(0) + key.e().body()
        key.setE(
            org.connectbot.sshlib.protocol.Mpint().apply {
                setLenBody(noncanonical.size.toLong())
                setBody(noncanonical)
                _check()
            },
        )
        key._check()
        assertFailsWith<SshException> { SshCertificate.decode(wire.toByteArray()) }
    }

    @Test
    fun `RSA certificate negotiation cannot be downgraded to another signature algorithm`() {
        val certificate = certificateFixture("host-rsa")
        val privateKey = requireNotNull(javaClass.getResource("/keys/rsa_unencrypted")).readText()
        val data = "exchange hash".toByteArray()
        val signature = SshSigning.sign("rsa-sha2-256$CERTIFICATE_SUFFIX", privateKey, null, data)
        assertTrue(SignatureVerifier.verify(certificate.encoded, signature, data, "rsa-sha2-256$CERTIFICATE_SUFFIX"))
        assertFalse(SignatureVerifier.verify(certificate.encoded, signature, data, "rsa-sha2-512$CERTIFICATE_SUFFIX"))
    }

    @Test
    fun `public snapshots cannot mutate certificate`() {
        val certificate = certificateFixture()
        certificate.encoded.fill(0)
        certificate.publicKey.encoded.fill(0)
        certificate.signatureKey.encoded.fill(0)
        assertTrue(validCertificateSignature(certificate))
    }

    @ParameterizedTest
    @ValueSource(strings = ["host-ed25519", "host-rsa", "host-ecdsa256", "host-ecdsa384", "host-ecdsa521", "host-ed25519-ca-rsa", "host-ed25519-ca-ecdsa"])
    fun `verify supported host and CA key types`(name: String) = runTest {
        val certificate = certificateFixture(name)
        val verifier = CertificateAuthorityVerifier("server.example.test", listOf(certificate.signatureKey))
        assertTrue(verifier.verify(PublicKey(certificate.algorithmName, certificate.encoded)))
        assertFalse(CertificateAuthorityVerifier("unrelated.invalid", listOf(certificate.signatureKey)).verify(PublicKey(certificate.algorithmName, certificate.encoded)))
    }

    @Test
    fun `host certificate checks include type clock principal critical options and CA trust`() = runTest {
        val key = certificatePublicKey()
        val ca = listOf(certificateAuthority())
        val certificate = certificateFixture()
        assertTrue(verifyHostCertificate(key, "localhost", ca, now = certificate.validAfter.toLong()))
        assertFalse(verifyHostCertificate(key, "localhost", ca, now = certificate.validAfter.toLong() - 1))
        assertFalse(verifyHostCertificate(key, "localhost", ca, now = certificate.validBefore.toLong()))
        assertFalse(verifyHostCertificate(key, "localhost", listOf(certificateAuthority("rsa"))))
        assertFalse(verifyHostCertificate(certificatePublicKey("user-ed25519"), "certificate-access", ca))
        assertFalse(verifyHostCertificate(certificatePublicKey("host-expired"), "localhost", ca))
        assertFalse(verifyHostCertificate(certificatePublicKey("host-critical"), "localhost", ca))
        assertFalse(CertificateAuthorityVerifier("localhost", ca).verify(certificate.publicKey))
        assertFalse(verifyHostCertificate(PublicKey("ssh-rsa$CERTIFICATE_SUFFIX", key.encoded), "localhost", ca))
    }

    @Test
    fun `changes to signed metadata invalidate CA signature`() {
        val original = certificateFixture()
        val wire = WireCertificate(ByteBufferKaitaiStream(original.encoded)).apply { _read() }
        wire.setKeyId(createByteString("forged".toByteArray()))
        wire._check()
        val tampered = SshCertificate.decode(wire.toByteArray())
        assertFalse(validCertificateSignature(tampered))
    }

    @Test
    fun `possession proof and agent binding use the certified key and raw signature name`() {
        val certificate = certificateFixture()
        val privateKey = requireNotNull(javaClass.getResource("/openssh-server/test_ed25519")).readText()
        val data = "exchange hash".toByteArray()
        val signature = SshSigning.sign(certificate.algorithmName, privateKey, null, data)
        assertTrue(SignatureVerifier.verify(certificate.encoded, signature, data, certificate.algorithmName))
        assertTrue(SignatureVerifier.verifyWithKeyType(certificate.encoded, signature, data))
        assertFalse(SignatureVerifier.verify(certificate.encoded, signature, data, "ssh-ed25519"))
        assertFalse(SignatureVerifier.verify(certificate.encoded, signature, data, "rsa-sha2-512$CERTIFICATE_SUFFIX"))
        assertFalse(SignatureVerifier.verify(certificate.encoded, signature, "wrong".toByteArray(), certificate.algorithmName))
    }

    @Test
    fun `hostname globs treat regex characters literally and handle repeated stars`() {
        assertTrue(matchHostPattern("*.EXAMPLE.test", "server.example.TEST"))
        assertTrue(matchHostPattern("host[12].example.test", "host[12].example.test"))
        assertFalse(matchHostPattern("host[12].example.test", "host1.example.test"))
        assertTrue(matchHostPattern("a**?*z", "abcdez"))
        assertFalse(matchHostPattern("a*".repeat(100) + "z", "a".repeat(200)))
        assertTrue(matchHostPattern("*", ""))
    }

    @Test
    fun `known hosts supports scoped authorities revocations safe patterns and ports`() = runTest {
        val ca = certificateResource("ca-ed25519.pub").toString(Charsets.UTF_8).trim()
        val key = certificatePublicKey()
        fun verifier(pattern: String, hostname: String = "localhost", port: Int = 22, extra: String = ""): KnownHostsVerifier {
            val file = directory.resolve("known_hosts").toFile()
            file.writeText("@cert-authority $pattern $ca\n$extra")
            return KnownHostsVerifier(file, hostname, port)
        }
        assertTrue(verifier("localhost").verify(key))
        assertTrue(verifier("[localhost]:2222", port = 2222).verify(key))
        assertTrue(verifier("*.example.test,!blocked.example.test", "allowed.example.test").verify(key))
        assertFalse(verifier("*.example.test,!blocked.example.test", "blocked.example.test").verify(key))
        assertFalse(verifier("host[12].example.test", "host1.example.test").verify(key))
        assertFalse(verifier("localhost", extra = "@revoked localhost $ca").verify(key))
        val raw = requireNotNull(javaClass.getResource("/openssh-server/test_ed25519.pub")).readText().trim()
        assertFalse(verifier("localhost", extra = "@revoked localhost $raw").verify(key))
        val certificateLine = certificateResource("host-ed25519-cert.pub").toString(Charsets.UTF_8).trim()
        assertFalse(verifier("localhost", extra = "@revoked localhost $certificateLine").verify(key))
        val file = directory.resolve("plain").toFile().apply { writeText("localhost $ca") }
        assertFalse(KnownHostsVerifier(file, "localhost").verify(key))
    }
}
