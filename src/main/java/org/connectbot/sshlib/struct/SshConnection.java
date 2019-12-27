package org.connectbot.sshlib.struct;

public interface SshConnection {
    void sendBanner();
    void disconnect();
}
