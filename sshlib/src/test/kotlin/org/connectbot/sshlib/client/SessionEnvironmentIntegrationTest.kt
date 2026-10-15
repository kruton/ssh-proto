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

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SftpOpenFlag
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.client.sftp.SftpClientImpl
import org.connectbot.sshlib.getOrThrow
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.io.ByteArrayOutputStream
import java.util.UUID
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@Testcontainers
class SessionEnvironmentIntegrationTest {
    companion object {
        private fun server(internal: Boolean): GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("openssh-env-test-10.6p1-v1", false)
                .withFileFromClasspath(".", "openssh-server")
                .withFileFromClasspath("test_rsa.pub", "keys/rsa_unencrypted.pub"),
        ).withExposedPorts(22)
            .withCommand(*if (internal) arrayOf("/usr/sbin/sshd", "-D", "-e", "-o", "ForceCommand=internal-sftp") else arrayOf("/usr/sbin/sshd", "-D", "-e"))
            .waitingFor(Wait.forLogMessage(".*Server listening.*", 1))

        @Container
        @JvmStatic
        val external = server(false)

        @Container
        @JvmStatic
        val internal = server(true)
    }

    private val verifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private suspend fun connect(server: GenericContainer<*>): SshClient {
        val client = SshClient(
            SshClientConfig {
                host = server.host
                port = server.getMappedPort(22)
                hostKeyVerifier = verifier
                environment = linkedMapOf("CBSSH_TEST_VALUE" to "default", "CBSSH_REJECTED" to "ignored")
                autoDisconnectOnLastChannelClose = false
            },
        )
        assertEquals(ConnectResult.Success, client.connect())
        assertEquals(AuthResult.Success, client.authenticatePassword("testuser", "testpass"))
        return client
    }

    @Test
    fun `OpenSSH accepts configured variables and explicit replacements before exec`(): Unit = runBlocking {
        withTimeout(30_000) {
            val client = connect(external)
            try {
                repeat(2) { index ->
                    val session = assertNotNull(client.openSession())
                    assertFalse(session.requestEnv("CBSSH_REJECTED", "ignored"))
                    val expected = if (index == 0) "default" else "値🌍"
                    if (index != 0) assertTrue(session.requestEnv("CBSSH_TEST_VALUE", expected))
                    assertTrue(session.requestEnv("CBSSH_TEST_EMPTY", ""))
                    assertTrue(session.requestExec("printf '%s|%s|%s' \"\$CBSSH_TEST_VALUE\" \"\${CBSSH_TEST_EMPTY-unset}\" \"\${CBSSH_REJECTED-unset}\""))
                    val output = ByteArrayOutputStream()
                    for (data in session.stdout) output.write(data)
                    assertEquals("$expected||unset", output.toString(Charsets.UTF_8))
                    session.close()
                }
            } finally {
                client.disconnect()
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = [false, true])
    fun `rejected env requests leave external and internal SFTP usable`(useInternal: Boolean): Unit = runBlocking {
        withTimeout(30_000) {
            val client = connect(if (useInternal) internal else external)
            try {
                // Public openSftp must survive ignored config defaults.
                val automatic = client.openSftp().getOrThrow()
                assertTrue(automatic.stat("/").getOrThrow().permissions != null)
                automatic.close()

                // Retain the SSH session to test rejection after SFTP has started.
                val session = assertNotNull(client.openSession())
                assertFalse(session.requestEnv("CBSSH_REJECTED", "ignored"))
                assertTrue(session.requestSubsystem("sftp"))
                val sftp = SftpClientImpl.create(session).getOrThrow()
                try {
                    assertFalse(session.requestEnv("CBSSH_TEST_VALUE", "too late"))
                    assertTrue(session.isOpen)
                    val path = "/tmp/cbssh-env-${UUID.randomUUID()}"
                    val content = "SFTP survived env rejection".toByteArray()
                    val handle = sftp.open(path, setOf(SftpOpenFlag.READ, SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE)).getOrThrow()
                    try {
                        sftp.write(handle, 0, content).getOrThrow()
                        assertContentEquals(content, sftp.read(handle, 0, content.size).getOrThrow())
                    } finally {
                        sftp.close(handle).getOrThrow()
                        sftp.remove(path).getOrThrow()
                    }
                } finally {
                    sftp.close()
                }
            } finally {
                client.disconnect()
            }
        }
    }
}
