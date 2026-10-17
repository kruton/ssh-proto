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

package org.connectbot.sshlib.protocol

import java.math.BigInteger

/** Decode an SSH mpint as a signed integer, including the empty encoding of zero. */
fun Mpint.toBigInteger(): BigInteger = body().let { if (it.isEmpty()) BigInteger.ZERO else BigInteger(it) }

/** Decode a key component that must be strictly positive, rejecting zero and negative values. */
fun Mpint.toPositiveBigInteger(): BigInteger = toBigInteger().also {
    require(it.signum() > 0) { "Expected a strictly positive SSH mpint" }
}
