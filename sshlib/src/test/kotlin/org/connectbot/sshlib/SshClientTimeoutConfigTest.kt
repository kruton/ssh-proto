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

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SshClientTimeoutConfigTest {
    private fun config(block: SshClientConfig.Builder.() -> Unit = {}) = SshClientConfig {
        host = "localhost"
        hostKeyVerifier = object : HostKeyVerifier {
            override suspend fun verify(key: PublicKey): Boolean = true
        }
        block()
    }

    @Test
    fun `existing timeout defaults are preserved`() {
        val config = config()
        assertEquals(30_000L, config.sftpRequestTimeoutMs)
        assertEquals(30_000L, config.hostKeyUpdateTimeoutMs)
        assertEquals(5_000L, config.disconnectTimeoutMs)
    }

    @ParameterizedTest
    @ValueSource(longs = [0, 100, 120_000])
    fun `timeout overrides include unlimited waits`(timeoutMs: Long) {
        val config = config {
            sftpRequestTimeoutMs = timeoutMs
            hostKeyUpdateTimeoutMs = timeoutMs
            disconnectTimeoutMs = timeoutMs
        }
        assertEquals(timeoutMs, config.sftpRequestTimeoutMs)
        assertEquals(timeoutMs, config.hostKeyUpdateTimeoutMs)
        assertEquals(timeoutMs, config.disconnectTimeoutMs)
    }

    @Test
    fun `each negative timeout is rejected`() {
        assertFailsWith<IllegalArgumentException> { config { sftpRequestTimeoutMs = -1 } }
        assertFailsWith<IllegalArgumentException> { config { hostKeyUpdateTimeoutMs = -1 } }
        assertFailsWith<IllegalArgumentException> { config { disconnectTimeoutMs = -1 } }
    }
}
