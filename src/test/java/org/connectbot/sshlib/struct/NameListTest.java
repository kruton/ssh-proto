package org.connectbot.sshlib.struct;

import org.junit.Test;

import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class NameListTest {
    @Test
    public void clientPreferred_Success() throws Exception {
        NameList clientList = new NameList(Arrays.asList("foo", "bar"), false);
        NameList serverList = new NameList(Arrays.asList("bar", "foo"), true);
        assertThat(clientList.findPreferred(serverList), is("foo"));
        assertThat(serverList.findPreferred(clientList), is("foo"));
    }

    @Test
    public void clientPreferred_FunctionSetAfterward_Success() throws Exception {
        NameList clientList = new NameList(Arrays.asList("foo", "bar"));
        clientList.setServer(false);
        NameList serverList = new NameList(Arrays.asList("bar", "foo"));
        serverList.setServer(true);
        assertThat(clientList.findPreferred(serverList), is("foo"));
        assertThat(serverList.findPreferred(clientList), is("foo"));
    }

    @Test(expected = NameList.NoCommonSelectionException.class)
    public void noMatchingAlgorithms_Failure() throws Exception {
        NameList clientList = new NameList(Arrays.asList("foo", "bar"), false);
        NameList serverList = new NameList(Arrays.asList("baz", "ham"), true);
        clientList.findPreferred(serverList);
    }

    @Test(expected = NameList.NoCommonSelectionException.class)
    public void bothServers_Failure() throws Exception {
        NameList server1List = new NameList(Arrays.asList("foo", "bar"), true);
        NameList server2List = new NameList(Arrays.asList("bar", "foo"), true);
        server1List.findPreferred(server2List);
    }

    @Test(expected = NameList.NoCommonSelectionException.class)
    public void bothClients_Failure() throws Exception {
        NameList client1List = new NameList(Arrays.asList("foo", "bar"), false);
        NameList client2List = new NameList(Arrays.asList("bar", "foo"), false);
        client1List.findPreferred(client2List);
    }

    @Test(expected = NameList.NoCommonSelectionException.class)
    public void firstFunctionNotSet_Failure() throws Exception {
        NameList clientList = new NameList(Arrays.asList("foo", "bar"));
        NameList serverList = new NameList(Arrays.asList("bar", "foo"), true);
        clientList.findPreferred(serverList);
    }

    @Test(expected = NameList.NoCommonSelectionException.class)
    public void secondFunctionNotSet_Failure() throws Exception {
        NameList clientList = new NameList(Arrays.asList("foo", "bar"), false);
        NameList serverList = new NameList(Arrays.asList("bar", "foo"));
        clientList.findPreferred(serverList);
    }
}