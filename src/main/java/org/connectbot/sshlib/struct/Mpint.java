/*
 * Copyright 2019 Kenny Root
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

package org.connectbot.sshlib.struct;

import java.math.BigInteger;

import io.kaitai.struct.KaitaiStream;

public class Mpint {
    private final KaitaiStream _io;
    private BigInteger _value;

    public Mpint(KaitaiStream io) {
        this._io = io;
    }

    public void _read() {
        long len = _io.readU4be();
        byte[] buf = _io.readBytes(len);

        if (buf.length == 0) {
            _value = BigInteger.ZERO;
        } else {
            _value = new BigInteger(1, buf);
        }
    }

    public void _write(KaitaiStream io) {
        byte[] encoded = _value.toByteArray();
        io.writeU4be(encoded.length);
        io.writeBytes(encoded);
    }

    public BigInteger getValue() {
        return _value;
    }
}
