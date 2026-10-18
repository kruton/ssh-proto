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

import com.github.dockerjava.api.model.ExposedPort
import com.github.dockerjava.api.model.PortBinding
import com.github.dockerjava.api.model.Ports
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.blocking.BlockingSshClient
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.time.Duration
import java.util.Base64
import java.util.concurrent.TimeUnit

class LegacyOpenSshCompatibilityTest {
    data class Server(val version: String, val sha256: String, val protocol: String = "2") {
        override fun toString(): String = "$version (Protocol $protocol)"
    }

    companion object {
        @JvmStatic
        fun servers() = listOf(
            Server("3.7.1p2", "c77c45cda120a2df844639ed9545243e9c9a436bd723e556c9ea06c15a682d06"),
            Server("5.0p1", "73a58620cd475155be8524f46997ba1942bc9e54204eeb15f0465e54ca279f4f"),
            Server("5.3p1", "d0c917462896974480b14454a8e1cb8b809291f67e5b9779c9b4dc4156c5ef12"),
            Server("5.3p1", "d0c917462896974480b14454a8e1cb8b809291f67e5b9779c9b4dc4156c5ef12", "1,2"),
            Server("7.4p1", "1b1fc4a14e2024293181924ed24872e6f2e06293f3e8926a376b8aec481f19d1"),
        )
    }

    @ParameterizedTest(name = "OpenSSH {0}")
    @MethodSource("servers")
    @Timeout(value = 10, unit = TimeUnit.MINUTES)
    fun `legacy identification permits verified key exchange authentication and exec`(server: Server) {
        val image = ImageFromDockerfile("cbssh-legacy-openssh-${server.version}", false)
            .withFileFromClasspath(".", "legacy-openssh-server")
            .withBuildArg("OPENSSH_VERSION", server.version)
            .withBuildArg("OPENSSH_SHA256", server.sha256)
        GenericContainer(image).withExposedPorts(22)
            // Obsolete daemons must only be reachable from this test host.
            .withCreateContainerCmdModifier { command ->
                command.hostConfig!!.withPortBindings(
                    PortBinding(Ports.Binding.bindIpAndPort("127.0.0.1", 0), ExposedPort.tcp(22)),
                )
            }
            .withCommand("/opt/ssh/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config", "-o", "Protocol=${server.protocol}")
            .waitingFor(Wait.forLogMessage(".*Server listening.*", 1).withStartupTimeout(Duration.ofSeconds(60)))
            .use { container ->
                container.start()
                val host = container.host
                val port = container.getMappedPort(22)
                val protocol = if (server.protocol == "1,2") "1.99" else "2.0"
                val ending = if (server.version == "5.3p1" && protocol == "2.0") "\r\n" else "\n"
                // Later portable releases omit the portable patch suffix on the wire.
                val advertisedVersion = if (server.version == "3.7.1p2") server.version else server.version.substringBefore('p')
                val expectedBanner = "SSH-$protocol-OpenSSH_$advertisedVersion$ending"
                // Check the real daemon's bytes independently of the reader being tested.
                Socket(host, port).use probe@{ socket ->
                    socket.soTimeout = 10_000
                    socket.getOutputStream().write("SSH-2.0-CBSSH_BannerProbe\r\n".toByteArray(Charsets.US_ASCII))
                    val bytes = ByteArrayOutputStream()
                    repeat(255) {
                        val byte = socket.getInputStream().read()
                        check(byte >= 0) { "Server closed before its identification" }
                        bytes.write(byte)
                        if (byte == 10) {
                            assertEquals(expectedBanner, bytes.toString(Charsets.US_ASCII))
                            return@probe
                        }
                    }
                    error("Server identification exceeds 255 bytes")
                }

                val hostKey = container.execInContainer("cat", "/etc/ssh/ssh_host_rsa_key.pub")
                assertEquals(0, hostKey.exitCode)
                val fields = hostKey.stdout.trim().split(' ')
                val expectedKey = PublicKey(fields[0], Base64.getDecoder().decode(fields[1]))
                var verified = false
                val client = BlockingSshClient(
                    SshClientConfig {
                        this.host = host
                        this.port = port
                        hostKeyVerifier = object : HostKeyVerifier {
                            override suspend fun verify(key: PublicKey): Boolean {
                                assertEquals(expectedKey, key)
                                verified = true
                                return true
                            }
                        }
                        // Opt in locally; this test must never weaken library defaults.
                        kexAlgorithms = "curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
                        hostKeyAlgorithms = "ssh-rsa"
                        encryptionAlgorithms = "aes128-ctr,aes128-cbc"
                        macAlgorithms = "hmac-sha1"
                    },
                )
                try {
                    client.connect()
                    assertTrue(verified)
                    client.authenticatePassword("testuser", "testpass")
                    val session = client.openSession()
                    assertNotNull(session)
                    session!!.use {
                        runBlocking {
                            withTimeout(10_000) {
                                assertTrue(session.requestExec("printf legacy-banner-ok"))
                                val output = ByteArrayOutputStream()
                                for (bytes in session.stdout) output.write(bytes)
                                assertEquals("legacy-banner-ok", output.toString(Charsets.US_ASCII))
                            }
                        }
                    }
                } finally {
                    client.disconnect()
                }
            }
    }
}
