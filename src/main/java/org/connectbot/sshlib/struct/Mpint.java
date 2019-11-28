package org.connectbot.sshlib.struct;

import java.math.BigInteger;

import io.kaitai.struct.KaitaiStream;

public class Mpint {
    private final BigInteger value;

    public Mpint(KaitaiStream io) {
        long len = io.readU4be();
        byte[] buf = io.readBytes(len);

        if (buf.length == 0) {
            value = BigInteger.ZERO;
        } else {
            value = new BigInteger(1, buf);
        }
    }

    public BigInteger getValue() {
        return value;
    }
}
