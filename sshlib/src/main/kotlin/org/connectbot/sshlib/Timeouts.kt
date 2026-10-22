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

import kotlinx.coroutines.withTimeout

/** Timeouts in milliseconds, kept separate so each operation can be tuned independently. */
internal object Timeouts {
    const val DEFAULT_HANDSHAKE_TIMEOUT_MS = 30_000L
    const val DEFAULT_SFTP_REQUEST_TIMEOUT_MS = 30_000L
    const val DEFAULT_HOST_KEY_UPDATE_TIMEOUT_MS = 30_000L
    const val DEFAULT_DISCONNECT_TIMEOUT_MS = 5_000L
}

/** A zero deadline waits until completion or cancellation. */
internal suspend fun <T> withOptionalTimeout(timeoutMs: Long, block: suspend () -> T): T = if (timeoutMs == 0L) block() else withTimeout(timeoutMs) { block() }
