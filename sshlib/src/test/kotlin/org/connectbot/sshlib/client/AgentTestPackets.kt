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

/** Build raw requests, including unknown types and intentionally malformed payloads. */
internal fun buildAgentMessage(messageType: Int, payload: ByteArray): ByteArray {
    val totalLength = 1L + payload.size
    val stream = ByteBufferKaitaiStream(4 + totalLength)
    stream.writeU4be(totalLength)
    stream.writeU1(messageType)
    stream.writeBytes(payload)
    stream.seek(0)
    return stream.readBytesFull()
}
