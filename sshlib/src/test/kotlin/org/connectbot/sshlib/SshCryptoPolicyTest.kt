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

package org.connectbot.sshlib

import org.connectbot.sshlib.crypto.DiffieHellmanGroupExchange
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SshCryptoPolicyTest {
    @Test fun `future requires hybrid and 256 bit encryption`() {
        val policy = SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE)
        assertEquals(3072, policy.minimumRsaBits)
        assertEquals(3072, policy.minimumDhBits)
        assertTrue(policy.algorithms.getValue(AlgorithmCategory.KEX).all { "x25519" in it || "nistp" in it })
        assertTrue(policy.algorithms.getValue(AlgorithmCategory.KEX).none { it == "curve25519-sha256" })
        assertTrue(policy.algorithms.getValue(AlgorithmCategory.CIPHER).none { "128" in it || "cbc" in it })
    }

    @Test fun `custom expressions preserve ordering and skip unknown names`() {
        val policy = SshCryptoPolicy.resolve(overrides = mapOf(AlgorithmCategory.KEX to "^curve25519-sha256,+diffie-hellman-group1-sha1,-ecdh-sha2-nistp256,+future-algorithm"), minimumDhBits = 1024)
        val algorithms = policy.algorithms.getValue(AlgorithmCategory.KEX)
        assertEquals("curve25519-sha256", algorithms.first())
        assertEquals("diffie-hellman-group1-sha1", algorithms.last())
        assertFalse("ecdh-sha2-nistp256" in algorithms)
        assertEquals(listOf(AlgorithmPolicyWarning(AlgorithmCategory.KEX, "future-algorithm", AlgorithmPolicyWarningReason.UNSUPPORTED)), policy.warnings)
    }

    @Test fun `explicit algorithms do not override DH minimum`() {
        val policy = SshCryptoPolicy.resolve(overrides = mapOf(AlgorithmCategory.KEX to "diffie-hellman-group1-sha1"))
        assertTrue(policy.algorithms.getValue(AlgorithmCategory.KEX).isEmpty())
        assertEquals(AlgorithmPolicyWarningReason.DH_TOO_SMALL, policy.warnings.single().reason)
    }

    @Test fun `FIPS excludes non profile methods and legacy enables compatibility`() {
        val fips = SshCryptoPolicy.resolve(CryptoPolicyPreset.FIPS)
        assertTrue(fips.algorithms.getValue(AlgorithmCategory.CIPHER).all { it.startsWith("aes") && "cbc" !in it })
        assertFalse("ssh-ed25519" in fips.algorithms.getValue(AlgorithmCategory.HOST_KEY))
        assertFalse("diffie-hellman-group-exchange-sha256" in fips.algorithms.getValue(AlgorithmCategory.KEX))
        val legacy = SshCryptoPolicy.resolve(CryptoPolicyPreset.LEGACY)
        assertEquals(1024, legacy.minimumDhBits)
        assertTrue("ssh-rsa" in legacy.algorithms.getValue(AlgorithmCategory.PUBKEY))
        assertTrue("3des-cbc" in legacy.algorithms.getValue(AlgorithmCategory.CIPHER))
    }

    @Test fun `malformed and conflicting expressions fail`() {
        for (expression in listOf("+ssh-rsa,-ssh-rsa", "ssh-rsa,+ssh-ed25519", "+", "ssh-rsa,", "-rsa*")) {
            assertThrows(SshException::class.java) { SshCryptoPolicy.validateExpression(expression) }
        }
        SshCryptoPolicy.validateExpression("+not-yet-supported@example.com")
    }

    @Test fun `RSA limits apply to parsed public key material`() {
        val pair = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val blob = SshSigning.encodePublicKeyBlob(pair.public)
        assertTrue(SshCryptoPolicy.resolve().acceptsKey(blob, AlgorithmCategory.HOST_KEY))
        assertFalse(SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE).acceptsKey(blob, AlgorithmCategory.HOST_KEY))
        assertFalse(SshCryptoPolicy.resolve(CryptoPolicyPreset.FUTURE).acceptsKey(blob, AlgorithmCategory.PUBKEY))
    }

    @Test fun `group exchange minimum is reflected in request parameters`() {
        val gex = DiffieHellmanGroupExchange("SHA-256", 6144)
        assertEquals(6144, gex.min)
        assertEquals(6144, gex.n)
        assertEquals(8192, gex.max)
    }

    @Test
    fun `certificate authorities must meet the selected signature policy`() {
        val text = javaClass.getResource("/certificates/host-ecdsa256-cert.pub")!!.readText()
        val certificate = SshCertificate.decode(text)
        assertTrue(SshCryptoPolicy.resolve().acceptsKey(certificate.encoded, AlgorithmCategory.HOST_KEY))
        assertFalse(SshCryptoPolicy.resolve(CryptoPolicyPreset.FIPS).acceptsKey(certificate.encoded, AlgorithmCategory.HOST_KEY))
    }

    @Test
    @org.junit.jupiter.api.parallel.ResourceLock("JCA_PROVIDERS")
    fun `catalog reflects provider removal and restoration in the same process`() {
        val original = java.security.Security.getProviders().toList()
        val implementations = original.filter { it.getService("Signature", "Ed448") != null }
        org.junit.jupiter.api.Assumptions.assumeTrue(implementations.isNotEmpty())
        fun available() = SshCryptoPolicy.catalog().getValue(AlgorithmCategory.HOST_KEY).first { it.name == "ssh-ed448" }.available
        assertTrue(available())
        try {
            implementations.forEach { java.security.Security.removeProvider(it.name) }
            assertFalse(available())
        } finally {
            original.forEachIndexed { index, provider ->
                if (java.security.Security.getProvider(provider.name) == null) java.security.Security.insertProviderAt(provider, index + 1)
            }
        }
        assertTrue(available())
    }
}
