package org.tcpid.opretj;

public interface OPRETECEventListener {
    void onOPRETRevoke(final byte[] pkhash, final byte[] sig);
}
