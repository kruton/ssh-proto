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

import io.kaitai.struct.KaitaiStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class NameList extends ArrayList<String> {
    private KaitaiStream _io;

    private Boolean server;

    public NameList(Collection<String> namesList) {
        super();
        addAll(namesList);
    }

    public NameList(Collection<String> namesList, boolean isServer) {
        this(namesList);
        server = isServer;
    }

    public NameList(KaitaiStream io) {
        super();
        this._io = io;
    }

    public void _read() {
        long len = _io.readU4be();
        byte[] buf = _io.readBytes(len);
        String fullList = new String(buf, StandardCharsets.ISO_8859_1);
        addAll(Arrays.asList(fullList.split(",", -1)));
    }

    public void _write(KaitaiStream io) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < size(); i++) {
            try {
                byte[] encoded = get(i).getBytes(StandardCharsets.ISO_8859_1);
                baos.write(encoded);
                if (i != 0)
                    baos.write(',');
            } catch (IOException ignored) {
            }
        }
        byte[] value = baos.toByteArray();
        io.writeU4be(value.length);
        io.writeBytes(value);
    }

    public void setServer(boolean server) {
        this.server = server;
    }

    Boolean isServer() {
        return server;
    }

    public String findPreferred(NameList otherList) throws NoCommonSelectionException {
        if (server == null || otherList.isServer() == null) {
            throw new NoCommonSelectionException("Both sides must have server or client set");
        }

        if ((server && otherList.isServer()) || (!server && !otherList.isServer())) {
                throw new NoCommonSelectionException("One server and one client required");
        }

        if (server) {
            return findPreferred(otherList, this);
        } else {
            return findPreferred(this, otherList);
        }
    }

    private static String findPreferred(NameList clientList, NameList serverList) throws NoCommonSelectionException {
        for (String candidate : clientList) {
            for (String serverCandidate : serverList) {
                if (candidate.equals(serverCandidate)) {
                    return candidate;
                }
            }
        }
        throw new NoCommonSelectionException("Could not find common selection");
    }

    public static class NoCommonSelectionException extends Exception {
        public NoCommonSelectionException(String message) {
            super(message);
        }
    }
}
