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

import io.kaitai.struct.ByteBufferKaitaiStream
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.CertificateAuthorityVerifier
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.KnownHostsVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshKeyRevocationList
import org.connectbot.sshlib.SshKeys
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.certificateAuthority
import org.connectbot.sshlib.certificateFixture
import org.connectbot.sshlib.certificatePublicKey
import org.connectbot.sshlib.certificateResource
import org.connectbot.sshlib.protocol.UserauthPublickeySignatureDataAny
import org.connectbot.sshlib.sk.SkAlgorithm
import org.connectbot.sshlib.sk.SkPublicKeyDecoder
import org.connectbot.sshlib.sk.SkSignatureBlob
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.utility.MountableFile
import java.nio.file.Path
import java.security.MessageDigest
import java.security.Signature
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@Testcontainers
class CertificateAuthenticationIntegrationTest {
    companion object {
        private val leafResources = mapOf(
            "ed25519" to "openssh-server/test_ed25519",
            "rsa" to "keys/rsa_unencrypted",
            "ecdsa256" to "keys/ecdsa256_unencrypted",
            "ecdsa384" to "keys/ecdsa384_unencrypted",
            "ecdsa521" to "keys/ecdsa521_unencrypted",
        )

        private val image = ImageFromDockerfile("cbssh-certificate-test", false)
            .withFileFromClasspath(".", "openssh-server")
            .withFileFromClasspath("test_rsa.pub", "keys/rsa_unencrypted.pub")

        @Container
        @JvmStatic
        val server: GenericContainer<*> = GenericContainer(image)
            .withExposedPorts(22)
            .withCopyFileToContainer(MountableFile.forClasspathResource("certificates/ca-ed25519.pub"), "/etc/ssh/user_ca.pub")
            .apply {
                for ((kind, resource) in leafResources) {
                    withCopyFileToContainer(MountableFile.forClasspathResource(resource, 384), "/etc/ssh/cert_$kind")
                    withCopyFileToContainer(MountableFile.forClasspathResource("certificates/host-$kind-cert.pub"), "/etc/ssh/cert_$kind-cert.pub")
                }
            }
            .withCommand(
                "sh",
                "-c",
                "printf '%s\n' 'certificate-access' > /etc/ssh/certificate_principals; " +
                    "printf '%s\n' 'TrustedUserCAKeys /etc/ssh/user_ca.pub' " +
                    "'AuthorizedPrincipalsFile /etc/ssh/certificate_principals' > /etc/ssh/cert_sshd_config; " +
                    leafResources.keys.joinToString(" ") {
                        "printf '%s\n' 'HostKey /etc/ssh/cert_$it' 'HostCertificate /etc/ssh/cert_$it-cert.pub' >> /etc/ssh/cert_sshd_config;"
                    } +
                    " exec /usr/sbin/sshd -D -e -f /etc/ssh/cert_sshd_config",
            )
            .waitingFor(Wait.forLogMessage(".*Server listening.*", 1))
    }

    @TempDir
    lateinit var directory: Path

    private fun privateKey(kind: String): String = requireNotNull(javaClass.getResource("/" + leafResources.getValue(kind))).readText()

    private fun client(algorithm: String = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256", verifier: HostKeyVerifier = CertificateAuthorityVerifier("localhost", listOf(certificateAuthority()))): SshClient = SshClient(
        SshClientConfig {
            host = server.host
            port = server.getMappedPort(22)
            hostKeyVerifier = verifier
            hostKeyAlgorithms = algorithm
            enableCertificateHostKeys()
            rekeyBytesLimit = 8192
            rekeyIntervalMs = Long.MAX_VALUE
            autoDisconnectOnLastChannelClose = false
        },
    )

    @ParameterizedTest
    @ValueSource(strings = ["ed25519", "rsa", "ecdsa256", "ecdsa384", "ecdsa521"])
    fun `local certificate credentials authenticate using server-authorized principals`(kind: String) = runBlocking<Unit> {
        val client = client()
        try {
            assertIs<ConnectResult.Success>(client.connect())
            val certificate = certificateFixture("user-$kind")
            assertIs<AuthResult.Success>(client.authenticatePublicKey("testuser", privateKey(kind), certificate))
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"])
    fun `host certificates negotiate and verify for each supported algorithm`(algorithm: String) = runBlocking<Unit> {
        val client = client(algorithm)
        try {
            assertIs<ConnectResult.Success>(client.connect())
            assertEquals("$algorithm-cert-v01@openssh.com", client.connectionInfo?.serverHostKeyAlgorithm)
            assertIs<AuthResult.Success>(client.authenticatePublicKey("testuser", privateKey("ed25519"), certificateFixture("user-ed25519")))
        } finally {
            client.disconnect()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["ed25519", "rsa", "ecdsa256", "ecdsa384", "ecdsa521", "sk-ed25519", "sk-ecdsa256"])
    fun `external signers authenticate certificate identities including software security keys`(kind: String) = runBlocking<Unit> {
        val client = client("ssh-ed25519,rsa-sha2-512,rsa-sha2-256")
        val certificate = certificateFixture("user-$kind")
        var signed = false
        val handler = object : AuthHandler {
            override suspend fun onPublicKeysNeeded(): List<AuthPublicKey> = listOf(certificate.toAuthPublicKey())
            override suspend fun onPasswordNeeded(): String? = null
            override suspend fun onKeyboardInteractivePrompt(name: String, instruction: String, prompts: List<KeyboardInteractiveCallback.Prompt>): List<String>? = null
            override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray {
                signed = true
                val signedData = UserauthPublickeySignatureDataAny(ByteBufferKaitaiStream(dataToSign)).apply { _read() }
                assertEquals("publickey-hostbound-v00@openssh.com", signedData.methodName().value())
                assertContentEquals(certificate.encoded, signedData.publicKeyBlob().data())
                if (!kind.startsWith("sk-")) return SshSigning.sign(key.algorithmName, privateKey(kind), null, dataToSign)
                val sk = SkPublicKeyDecoder.decode(certificate.publicKey.encoded)
                val pair = SshKeys.decodePemPrivateKey(privateKey(kind.removePrefix("sk-")))
                val flags = SkSignatureBlob.FLAG_USER_PRESENCE
                val payload = sha256(sk.application.toByteArray()) + byteArrayOf(flags, 0, 0, 0, 1) + sha256(dataToSign)
                val signer = Signature.getInstance(if (sk.algorithm == SkAlgorithm.ED25519) "Ed25519" else "SHA256withECDSA")
                signer.initSign(pair.private)
                signer.update(payload)
                return SkSignatureBlob.pack(sk.algorithm, signer.sign(), flags, 1u)
            }
        }
        try {
            assertIs<ConnectResult.Success>(client.connect())
            assertIs<AuthResult.Success>(client.authenticate("testuser", handler))
            assertTrue(signed)
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `known hosts CA verifies on a nonstandard port and certificate rekey retains full blob`() = runBlocking<Unit> {
        val knownHosts = directory.resolve("known_hosts").toFile().apply {
            writeText("@cert-authority [localhost]:" + server.getMappedPort(22) + " " + certificateResource("ca-ed25519.pub").toString(Charsets.UTF_8))
        }
        val known = KnownHostsVerifier(knownHosts, "localhost", server.getMappedPort(22))
        var verified = 0
        var updated = false
        val client = client(
            verifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey): Boolean {
                    assertContentEquals(certificateFixture().encoded, key.encoded)
                    verified++
                    return known.verify(key)
                }
                override suspend fun addKeys(keys: List<PublicKey>) {
                    updated = true
                }
                override suspend fun removeKeys(keys: List<PublicKey>) {
                    updated = true
                }
            },
        )
        try {
            assertIs<ConnectResult.Success>(client.connect())
            assertIs<AuthResult.Success>(client.authenticatePublicKey("testuser", privateKey("ed25519"), certificateFixture("user-ed25519")))
            val session = assertNotNull(client.openSession())
            assertTrue(session.requestExec("dd if=/dev/zero bs=1024 count=128 2>/dev/null"))
            var bytes = 0
            withTimeout(30_000) {
                while (true) {
                    bytes += (session.read() ?: break).size
                }
            }
            assertEquals(128 * 1024, bytes)
            assertTrue(verified > 1, "Expected certificate verification during rekey")
            assertFalse(updated, "Certificate connections must not learn raw host keys")
            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `untrusted and revoked host certificates fail connection`() = runBlocking<Unit> {
        val verifiers = listOf(
            CertificateAuthorityVerifier("localhost", listOf(certificateAuthority("rsa"))),
            CertificateAuthorityVerifier("wrong.example.invalid", listOf(certificateAuthority())),
            CertificateAuthorityVerifier("localhost", listOf(certificateAuthority()), SshKeyRevocationList.decode(certificateResource("serial-list.krl"))),
        )
        for (verifier in verifiers) {
            val client = client(verifier = verifier)
            try {
                assertFalse(client.connect() is ConnectResult.Success)
            } finally {
                client.disconnect()
            }
        }
    }

    @Test
    fun `server enforces certificate critical restrictions and rejects expired user certificates`() = runBlocking<Unit> {
        val client = client()
        try {
            assertIs<ConnectResult.Success>(client.connect())
            assertIs<AuthResult.Failure>(client.authenticatePublicKey("testuser", privateKey("ed25519"), certificateFixture("user-expired")))
            assertIs<AuthResult.Success>(client.authenticatePublicKey("testuser", privateKey("ed25519"), certificateFixture("user-restricted")))
            val session = assertNotNull(client.openSession())
            assertTrue(session.requestExec("printf ignored"))
            val output = StringBuilder()
            withTimeout(10_000) {
                while (true) {
                    output.append((session.read() ?: break).toString(Charsets.UTF_8))
                }
            }
            assertEquals("certificate-restriction", output.toString())
            session.close()
        } finally {
            client.disconnect()
        }
    }

    @Test
    fun `mismatched private keys are rejected before sending authentication`() = runBlocking<Unit> {
        val client = client()
        try {
            assertIs<ConnectResult.Success>(client.connect())
            assertIs<AuthResult.Error>(client.authenticatePublicKey("testuser", privateKey("rsa"), certificateFixture("user-ed25519")))
            assertIs<AuthResult.Success>(client.authenticatePublicKey("testuser", privateKey("ed25519"), certificateFixture("user-ed25519")))
        } finally {
            client.disconnect()
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
