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

package org.connectbot.sshlib.crypto

/** Raw-key BC Poly1305 adapter. Every completed tag erases its one-time key. */
internal class Poly1305 {
    private val core = Poly1305Core()
    private var finished = true

    fun init(key: ByteArray) {
        require(key.size == 32) { "Poly1305 key must be 32 bytes" }
        core.clear()
        core.init(key)
        finished = false
    }

    fun update(data: ByteArray, offset: Int, length: Int) {
        check(!finished) { "Poly1305 is not initialized or already finished" }
        require(offset >= 0 && length >= 0 && offset <= data.size - length) { "Invalid input range" }
        core.update(data, offset, length)
    }

    fun finish(tag: ByteArray, offset: Int) {
        check(!finished) { "Poly1305 is not initialized or already finished" }
        require(offset >= 0 && offset <= tag.size - 16) { "Output buffer is too short" }
        try {
            core.doFinal(tag, offset)
        } finally {
            reset()
        }
    }

    fun reset() {
        core.clear()
        finished = true
    }
}
