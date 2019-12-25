package org.connectbot.sshlib.struct;

import io.kaitai.struct.ByteBufferKaitaiStream;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.InputStream;

public class CaptureTest {
    @Test
    public void serverToClient() throws Exception {
        InputStream is = CaptureTest.class.getResourceAsStream("server-to-client.cap");
        DataInputStream dis = new DataInputStream(is);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteBufferKaitaiStream bb = new ByteBufferKaitaiStream(bytes);
        Ssh.IdBanner banner = new Ssh.IdBanner(bb);

        while (printPlain(bb) != Ssh.MessageType.SSH_MSG_NEWKEYS) {}
        while (!bb.isEof()) {
            printEnc(bb);
        }
    }

    private Ssh.MessageType printPlain(ByteBufferKaitaiStream bb) {
        Ssh.UnencryptedPacket msg = new Ssh.UnencryptedPacket(bb);
        System.out.print("unencrypted msg: ");
        System.out.println(msg.payload().messageType());
        switch (msg.payload().messageType()) {
            case SSH_MSG_KEXINIT:
                Ssh.SshMsgKexinit init = (Ssh.SshMsgKexinit) msg.payload().body();
                System.out.print("serverHostKeyAlgorithms: ");
                System.out.println(init.serverHostKeyAlgorithms());
                break;
            case SSH_MSG_KEXDH_INIT:
                System.out.print("e: ");
                Ssh.SshMsgKexdhInit dhinit = (Ssh.SshMsgKexdhInit) msg.payload().body();
                System.out.println(dhinit.e().getValue().toString());
                break;
        }
        return msg.payload().messageType();
    }

    private void printEnc(ByteBufferKaitaiStream bb) {
        Ssh.EncryptedPacket msg = new Ssh.EncryptedPacket(bb, 16);
        System.out.print("encrypted size: ");
        System.out.println(msg.packetLength());
    }
}
