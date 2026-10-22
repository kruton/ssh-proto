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
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SshClientHandshakeConfigTest {
    private fun config(timeoutMs: Long? = null) = SshClientConfig {
        host = "localhost"
        hostKeyVerifier = object : HostKeyVerifier {
            override suspend fun verify(key: PublicKey): Boolean = true
        }
        timeoutMs?.let { handshakeTimeoutMs = it }
    }

    @Test
    fun `default and explicit handshake deadlines are preserved`() {
        assertEquals(30_000L, config().handshakeTimeoutMs)
        assertEquals(120_000L, config(120_000).handshakeTimeoutMs)
        assertEquals(0L, config(0).handshakeTimeoutMs)
    }

    @Test
    fun `negative handshake deadline is rejected`() {
        assertFailsWith<IllegalArgumentException> { config(-1) }
    }
}
