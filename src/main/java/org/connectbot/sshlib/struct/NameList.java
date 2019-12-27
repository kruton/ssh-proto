package org.connectbot.sshlib.struct;

import io.kaitai.struct.KaitaiStream;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class NameList extends ArrayList<String> {
    public static class NoCommonSelectionException extends Exception {
        public NoCommonSelectionException(String message) {
            super(message);
        }
    }

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
        long len = io.readU4be();
        byte[] buf = io.readBytes(len);
        String fullList = new String(buf, StandardCharsets.ISO_8859_1);
        addAll(Arrays.asList(fullList.split(",", -1)));
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
}
