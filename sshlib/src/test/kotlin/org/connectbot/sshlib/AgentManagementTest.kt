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

import kotlinx.coroutines.test.runTest
import org.connectbot.sshlib.client.AgentProtocolHandler
import org.connectbot.sshlib.client.AgentSessionInfo
import org.connectbot.sshlib.client.buildAgentMessage
import org.connectbot.sshlib.protocol.SshAgentEnums.MessageType
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.ECGenParameterSpec

class AgentManagementTest {
    private class Provider : AgentProvider {
        val keys = mutableListOf<KeyPair>()
        var passphrase: String? = null
        var confirmed = false
        var lifetime: Long? = null
        override suspend fun getIdentities() = AgentResult.Success(keys.map { AgentIdentity(it.public.encoded, "test") })
        override suspend fun signData(context: AgentSigningContext) = AgentResult.Success<ByteArray?>(null)
        override suspend fun addIdentity(keyPair: KeyPair, comment: String, confirmUse: Boolean, lifetimeSeconds: Long?): AgentResult<Boolean> {
            keys.add(keyPair)
            confirmed = confirmUse
            lifetime = lifetimeSeconds
            return AgentResult.Success(true)
        }
        override suspend fun removeIdentity(publicKeyBlob: ByteArray) = AgentResult.Success(keys.removeAll { it.public.encoded.contentEquals(publicKeyBlob) })
        override suspend fun removeAllIdentities(): AgentResult<Boolean> {
            keys.clear()
            return AgentResult.Success(true)
        }
        override suspend fun isLocked() = passphrase != null
        override suspend fun lock(passphrase: String): AgentResult<Boolean> {
            this.passphrase = passphrase
            return AgentResult.Success(true)
        }
        override suspend fun unlock(passphrase: String): AgentResult<Boolean> {
            if (this.passphrase != passphrase) return AgentResult.Success(false)
            this.passphrase = null
            return AgentResult.Success(true)
        }
    }

    private val provider = Provider()
    private val handler = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(), byteArrayOf()))
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    @Test
    fun `add remove and remove all identities round trip`() = runTest {
        assertEquals(6, handler.handleRequest(buildAgentMessage(17, rsaPayload()))[4].toInt())
        assertEquals(1, provider.keys.size)
        assertTrue(pair.public.encoded.contentEquals(provider.keys.single().public.encoded))
        assertEquals(6, handler.handleRequest(buildAgentMessage(18, field(pair.public.encoded)))[4].toInt())
        assertTrue(provider.keys.isEmpty())
        handler.handleRequest(buildAgentMessage(17, rsaPayload()))
        assertEquals(6, handler.handleRequest(buildAgentMessage(19, byteArrayOf()))[4].toInt())
        assertTrue(provider.keys.isEmpty())
    }

    @Test
    fun `lock applies across channels and only correct unlock restores access`() = runTest {
        handler.handleRequest(buildAgentMessage(17, rsaPayload()))
        assertEquals(6, handler.handleRequest(buildAgentMessage(22, field("secret".toByteArray())))[4].toInt())
        val otherChannel = AgentProtocolHandler(provider, AgentSessionInfo(byteArrayOf(), byteArrayOf()))
        assertEquals(5, otherChannel.handleRequest(buildAgentMessage(19, byteArrayOf()))[4].toInt())
        assertEquals(5, otherChannel.handleRequest(buildAgentMessage(17, rsaPayload()))[4].toInt())
        val listing = otherChannel.handleRequest(buildAgentMessage(11, byteArrayOf()))
        assertEquals(12, listing[4].toInt())
        assertTrue(listing.copyOfRange(5, 9).all { it == 0.toByte() })
        assertEquals(5, otherChannel.handleRequest(buildAgentMessage(23, field("wrong".toByteArray())))[4].toInt())
        assertEquals(6, otherChannel.handleRequest(buildAgentMessage(23, field("secret".toByteArray())))[4].toInt())
        assertEquals(6, otherChannel.handleRequest(buildAgentMessage(19, byteArrayOf()))[4].toInt())
        assertTrue(provider.keys.isEmpty())
    }

    @Test
    fun `confirmation constraint is preserved and unknown constraints are rejected`() = runTest {
        assertEquals(6, handler.handleRequest(buildAgentMessage(25, rsaPayload() + byteArrayOf(2)))[4].toInt())
        assertTrue(provider.confirmed)
        assertEquals(5, handler.handleRequest(buildAgentMessage(25, rsaPayload() + byteArrayOf(99)))[4].toInt())
        assertEquals(5, handler.handleRequest(buildAgentMessage(17, rsaPayload() + byteArrayOf(2)))[4].toInt())
        assertEquals(1, provider.keys.size)
    }

    @Test
    fun `lifetime constraint is unsigned and truncated lifetimes are rejected`() = runTest {
        val constraints = byteArrayOf(1, -1, -1, -1, -1, 2)
        assertEquals(6, handler.handleRequest(buildAgentMessage(25, rsaPayload() + constraints))[4].toInt())
        assertEquals(0xffff_ffffL, provider.lifetime)
        assertTrue(provider.confirmed)
        assertEquals(5, handler.handleRequest(buildAgentMessage(25, rsaPayload() + byteArrayOf(1, 0)))[4].toInt())
        assertEquals(1, provider.keys.size)
    }

    @Test
    fun `truncated keys and trailing management data do not mutate the provider`() = runTest {
        assertEquals(5, handler.handleRequest(buildAgentMessage(17, rsaPayload().dropLast(1).toByteArray()))[4].toInt())
        assertEquals(5, handler.handleRequest(buildAgentMessage(19, byteArrayOf(0)))[4].toInt())
        assertEquals(5, handler.handleRequest(buildAgentMessage(22, field("secret".toByteArray()) + byteArrayOf(0)))[4].toInt())
        assertTrue(provider.keys.isEmpty())
        assertEquals(null, provider.passphrase)
    }

    @ParameterizedTest
    @CsvSource("nistp256,secp256r1,SHA256withECDSA", "nistp384,secp384r1,SHA384withECDSA", "nistp521,secp521r1,SHA512withECDSA")
    fun `ECDSA identities preserve public and private keys`(curve: String, jcaCurve: String, signatureAlgorithm: String) = runTest {
        val original = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(jcaCurve)) }.generateKeyPair()
        val response = handler.handleRequest(buildAgentMessage(MessageType.ADD_IDENTITY.id().toInt(), ecPayload(original, curve)))
        assertEquals(MessageType.SUCCESS.id().toInt(), response[4].toInt())
        assertImportedKeySigns(original, signatureAlgorithm)
    }

    @Test
    fun `DSA identities preserve public and private keys`() = runTest {
        val original = KeyPairGenerator.getInstance("DSA").apply { initialize(1024) }.generateKeyPair()
        val publicKey = original.public as DSAPublicKey
        val privateKey = original.private as DSAPrivateKey
        val parameters = publicKey.params
        val payload = field("ssh-dss".toByteArray()) +
            listOf(parameters.p, parameters.q, parameters.g, publicKey.y, privateKey.x)
                .fold(byteArrayOf()) { bytes, number -> bytes + field(number.toByteArray()) } + field("test".toByteArray())
        val response = handler.handleRequest(buildAgentMessage(MessageType.ADD_IDENTITY.id().toInt(), payload))
        assertEquals(MessageType.SUCCESS.id().toInt(), response[4].toInt())
        assertImportedKeySigns(original, "SHA1withDSA")
    }

    @Test
    fun `invalid ECDSA curve point and scalar do not reach the provider`() = runTest {
        val original = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val invalidPayloads = listOf(
            ecPayload(original, "nistp384", keyType = "ecdsa-sha2-nistp256"),
            ecPayload(original, "unknown", keyType = "ecdsa-sha2-nistp256"),
            ecPayload(original, "nistp256", point = byteArrayOf(4)),
            ecPayload(original, "nistp256", point = ByteArray(65)),
            ecPayload(original, "nistp256", scalar = BigInteger.ZERO),
            ecPayload(original, "nistp256", scalar = BigInteger.valueOf(-1)),
        )
        for (payload in invalidPayloads) {
            val response = handler.handleRequest(buildAgentMessage(MessageType.ADD_IDENTITY.id().toInt(), payload))
            assertEquals(MessageType.FAILURE.id().toInt(), response[4].toInt())
            assertTrue(provider.keys.isEmpty())
        }
    }

    @Test
    fun `providers without management support deny mutations`() = runTest {
        val readOnly = object : AgentProvider {
            override suspend fun getIdentities() = AgentResult.Success(emptyList<AgentIdentity>())
            override suspend fun signData(context: AgentSigningContext) = AgentResult.Success<ByteArray?>(null)
        }
        val readOnlyHandler = AgentProtocolHandler(readOnly, AgentSessionInfo(byteArrayOf(), byteArrayOf()))
        val requests = listOf(
            MessageType.ADD_IDENTITY to rsaPayload(),
            MessageType.REMOVE_IDENTITY to field(pair.public.encoded),
            MessageType.REMOVE_ALL_IDENTITIES to byteArrayOf(),
            MessageType.LOCK to field("secret".toByteArray()),
            MessageType.UNLOCK to field("secret".toByteArray()),
        )
        for ((type, payload) in requests) {
            val response = readOnlyHandler.handleRequest(buildAgentMessage(type.id().toInt(), payload))
            assertEquals(MessageType.FAILURE.id().toInt(), response[4].toInt(), type.name)
        }
        val listing = readOnlyHandler.handleRequest(buildAgentMessage(MessageType.REQUEST_IDENTITIES.id().toInt(), byteArrayOf()))
        assertEquals(MessageType.IDENTITIES_ANSWER.id().toInt(), listing[4].toInt())
    }

    private fun assertImportedKeySigns(original: KeyPair, algorithm: String) {
        val imported = provider.keys.single()
        assertArrayEquals(original.public.encoded, imported.public.encoded)
        val data = "agent import signing test".toByteArray()
        val signature = Signature.getInstance(algorithm).run {
            initSign(imported.private)
            update(data)
            sign()
        }
        assertTrue(
            Signature.getInstance(algorithm).run {
                initVerify(original.public)
                update(data)
                verify(signature)
            },
        )
    }

    private fun ecPayload(
        keyPair: KeyPair,
        curve: String,
        point: ByteArray = ecPoint(keyPair.public as ECPublicKey),
        scalar: BigInteger = (keyPair.private as ECPrivateKey).s,
        keyType: String = "ecdsa-sha2-$curve",
    ): ByteArray = field(keyType.toByteArray()) + field(curve.toByteArray()) + field(point) + field(scalar.toByteArray()) + field("test".toByteArray())

    private fun ecPoint(key: ECPublicKey): ByteArray {
        val size = (key.params.curve.field.fieldSize + 7) / 8
        fun coordinate(value: BigInteger): ByteArray = value.toByteArray().takeLast(size).toByteArray().let {
            ByteArray(size - it.size) + it
        }
        return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
    }

    private fun rsaPayload(): ByteArray {
        val privateKey = pair.private as RSAPrivateCrtKey
        return field("ssh-rsa".toByteArray()) +
            listOf(privateKey.modulus, privateKey.publicExponent, privateKey.privateExponent, privateKey.crtCoefficient, privateKey.primeP, privateKey.primeQ)
                .fold(byteArrayOf()) { bytes, number -> bytes + field(number.toByteArray()) } + field("test".toByteArray())
    }

    private fun field(value: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        DataOutputStream(this).apply {
            writeInt(value.size)
            write(value)
        }
    }.toByteArray()
}
