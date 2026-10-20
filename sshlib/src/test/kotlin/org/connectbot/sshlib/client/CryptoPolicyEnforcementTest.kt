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

package org.connectbot.sshlib.client

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.AlgorithmCategory
import org.connectbot.sshlib.AlgorithmPolicyWarning
import org.connectbot.sshlib.AlgorithmPolicyWarningReason
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.CryptoPolicyPreset
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshCryptoPolicy
import org.connectbot.sshlib.SshException
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator

@OptIn(ExperimentalCoroutinesApi::class)
class CryptoPolicyEnforcementTest {
    private val verifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    @Test
    fun `FUTURE refuses a classical only server`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (client, remote) = PipedTransport.create()
        val server = FakeSshServer(remote, backgroundScope, dispatcher).apply { kexAlgorithms = "curve25519-sha256" }
        server.start(ignoreTransportErrors = true)
        val policy = SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE)
        val connection = SshConnection(client, hostKeyVerifier = verifier, kexAlgorithms = policy.algorithms.getValue(AlgorithmCategory.KEX).joinToString(","), hostKeyAlgorithms = policy.algorithms.getValue(AlgorithmCategory.HOST_KEY).joinToString(","), encryptionAlgorithms = policy.algorithms.getValue(AlgorithmCategory.CIPHER).joinToString(","), macAlgorithms = policy.algorithms.getValue(AlgorithmCategory.MAC).joinToString(","), cryptoPolicy = policy, coroutineDispatcher = dispatcher)
        try {
            assertFalse(connection.connect() is ConnectResult.Success)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `FUTURE negotiates hybrid KEX against independent server`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (client, remote) = PipedTransport.create()
        val server = FakeSshServer(remote, backgroundScope, dispatcher).apply {
            kexAlgorithms = "mlkem768x25519-sha256"
            encryptionAlgorithm = "aes256-ctr"
        }
        server.start()
        val policy = SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE)
        val connection = SshConnection(client, hostKeyVerifier = verifier, kexAlgorithms = policy.algorithms.getValue(AlgorithmCategory.KEX).joinToString(","), hostKeyAlgorithms = policy.algorithms.getValue(AlgorithmCategory.HOST_KEY).joinToString(","), encryptionAlgorithms = policy.algorithms.getValue(AlgorithmCategory.CIPHER).joinToString(","), macAlgorithms = policy.algorithms.getValue(AlgorithmCategory.MAC).joinToString(","), cryptoPolicy = policy, coroutineDispatcher = dispatcher)
        try {
            assertTrue(connection.connect() is ConnectResult.Success)
        } finally {
            connection.close()
        }
    }

    @Test
    fun `host key restrictions do not constrain RSA authentication and order is honored`() {
        val policy = SshCryptoPolicy.resolve(overrides = mapOf(AlgorithmCategory.HOST_KEY to "ssh-ed25519", AlgorithmCategory.PUBKEY to "rsa-sha2-256,rsa-sha2-512"))
        val connection = SshConnection(PipedTransport.create().first, hostKeyVerifier = verifier, hostKeyAlgorithms = "ssh-ed25519", pubkeyAlgorithms = "rsa-sha2-256,rsa-sha2-512", cryptoPolicy = policy)
        SshConnection::class.java.getDeclaredField("serverSigAlgs").apply { isAccessible = true }.set(connection, setOf("rsa-sha2-512", "rsa-sha2-256"))
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val algorithm = SshConnection::class.java.getDeclaredMethod("authenticationAlgorithm", AuthPublicKey::class.java).apply { isAccessible = true }
        assertEquals("rsa-sha2-256", algorithm.invoke(connection, SshSigning.encodePublicKey(pair)))
        val ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        assertNull(algorithm.invoke(connection, SshSigning.encodePublicKey(ed)))
    }

    @Test
    fun `undersized callback keys are rejected before a probe and produce diagnostic`() {
        val warnings = mutableListOf<AlgorithmPolicyWarning>()
        val policy = SshCryptoPolicy.resolve(minimumRsaBits = 3072)
        val connection = SshConnection(PipedTransport.create().first, hostKeyVerifier = verifier, cryptoPolicy = policy, onAlgorithmWarning = warnings::add)
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val algorithm = SshConnection::class.java.getDeclaredMethod("authenticationAlgorithm", AuthPublicKey::class.java).apply { isAccessible = true }
        assertNull(algorithm.invoke(connection, SshSigning.encodePublicKey(pair)))
        assertEquals(AlgorithmPolicyWarningReason.RSA_TOO_SMALL, warnings.single().reason)
    }

    @Test
    fun `builder cannot override FUTURE to enable classical KEX`() {
        assertThrows(SshException::class.java) {
            SshClientConfig {
                host = "localhost"
                hostKeyVerifier = verifier
                cryptoPolicy(SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE))
                kexAlgorithms = "curve25519-sha256"
            }
        }
    }

    @Test
    fun `standalone authentication list restricts non RSA keys without changing old callers`() {
        val key = SshSigning.encodePublicKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair())
        val explicit = SshConnection(PipedTransport.create().first, hostKeyVerifier = verifier, pubkeyAlgorithms = "rsa-sha2-512")
        val historical = SshConnection(PipedTransport.create().first, hostKeyVerifier = verifier, hostKeyAlgorithms = "rsa-sha2-512")
        val select = SshConnection::class.java.getDeclaredMethod("authenticationAlgorithm", AuthPublicKey::class.java).apply { isAccessible = true }
        assertNull(select.invoke(explicit, key))
        assertEquals("ssh-ed25519", select.invoke(historical, key))
    }
}
