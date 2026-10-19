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

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame

class CertificateHostKeyConfigTest {
    private val verifier = CertificateAuthorityVerifier("localhost", listOf(certificateAuthority()))
    private fun builder() = SshClientConfig.Builder().apply {
        host = "localhost"
        hostKeyVerifier = verifier
    }

    @Test
    fun `certificate algorithms are opt in and applied to the final configured list`() {
        val builder = builder()
        val defaults = builder.build().hostKeyAlgorithms
        assertFalse(defaults.contains("-cert-v01"))
        assertSame(builder, builder.enableCertificateHostKeys())
        builder.hostKeyAlgorithms = "ssh-ed25519,rsa-sha2-512"
        val expected = "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512"
        assertEquals(expected, builder.build().hostKeyAlgorithms)
        assertEquals("ssh-ed25519,rsa-sha2-512", builder.hostKeyAlgorithms)
        builder.enableCertificateHostKeys()
        assertEquals(expected, builder.build().hostKeyAlgorithms)
        builder.enableCertificateHostKeys(false)
        assertEquals(builder.hostKeyAlgorithms, builder.build().hostKeyAlgorithms)
    }

    @Test
    fun `restricted algorithms explicit certificates and unsupported counterparts are preserved`() {
        val builder = builder().enableCertificateHostKeys()
        builder.hostKeyAlgorithms = "ssh-ed25519"
        assertEquals("ssh-ed25519-cert-v01@openssh.com,ssh-ed25519", builder.build().hostKeyAlgorithms)
        builder.hostKeyAlgorithms = "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,ssh-ed448"
        assertEquals(builder.hostKeyAlgorithms, builder.build().hostKeyAlgorithms)
        builder.enableCertificateHostKeys(false)
        assertEquals(builder.hostKeyAlgorithms, builder.build().hostKeyAlgorithms)
    }
}
