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

import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.AuthHandler
import org.connectbot.sshlib.AuthPublicKey
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshSigning
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.security.KeyPairGenerator
import kotlin.test.assertIs

class SshMultiFactorAuthTest {
    @ParameterizedTest
    @ValueSource(strings = ["password", "keyboard-interactive", "publickey"])
    fun `key success continues with the newly advertised factor`(secondMethod: String) = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.start()
        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = object : HostKeyVerifier {
                override suspend fun verify(key: PublicKey) = true
            },
            coroutineDispatcher = dispatcher,
        )
        val generator = KeyPairGenerator.getInstance("Ed25519")
        val pairs = List(if (secondMethod == "publickey") 2 else 1) { generator.generateKeyPair() }
        val keys = pairs.map(SshSigning::encodePublicKey)
        val handler = object : AuthHandler {
            override suspend fun onPublicKeysNeeded() = keys
            override suspend fun onSignatureRequest(key: AuthPublicKey, dataToSign: ByteArray): ByteArray = SshSigning.signWithKeyPair(key.algorithmName, pairs[keys.indexOf(key)], dataToSign)
            override suspend fun onKeyboardInteractivePrompt(
                name: String,
                instruction: String,
                prompts: List<KeyboardInteractiveCallback.Prompt>,
            ) = prompts.map { "testpass" }
            override suspend fun onPasswordNeeded() = "testpass"
        }
        try {
            assertIs<ConnectResult.Success>(connection.connect())
            val authentication = backgroundScope.async(dispatcher) { connection.authenticate("user", handler) }
            withTimeout(5_000) {
                assertEquals("none", server.awaitUserauthRequest().methodName().value())
                server.sendUserauthFailure(setOf("publickey"), false)
                assertEquals("publickey", server.awaitUserauthRequest().methodName().value())
                server.sendUserauthPkOk(keys[0].algorithmName, keys[0].publicKeyBlob)
                assertEquals("publickey", server.awaitUserauthRequest().methodName().value())
                server.sendUserauthFailure(setOf(secondMethod), true)
                assertEquals(secondMethod, server.awaitUserauthRequest().methodName().value())
                if (secondMethod == "publickey") {
                    server.sendUserauthPkOk(keys[1].algorithmName, keys[1].publicKeyBlob)
                    assertEquals("publickey", server.awaitUserauthRequest().methodName().value())
                }
                server.sendUserauthSuccess()
                assertIs<AuthResult.Success>(authentication.await())
            }
        } finally {
            connection.close()
        }
    }
}
