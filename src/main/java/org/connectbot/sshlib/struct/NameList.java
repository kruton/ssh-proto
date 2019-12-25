package org.connectbot.sshlib.struct;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import io.kaitai.struct.KaitaiStream;

public class NameList extends ArrayList<String> {
    public NameList(KaitaiStream io) {
        super();
        long len = io.readU4be();
        byte[] buf = io.readBytes(len);
        String fullList = new String(buf, StandardCharsets.ISO_8859_1);
        addAll(Arrays.asList(fullList.split(",", -1)));
    }
}
