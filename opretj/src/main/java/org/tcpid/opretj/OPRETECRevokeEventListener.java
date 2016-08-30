package org.tcpid.opretj;


public interface OPRETECRevokeEventListener {
    void onOPRETRevoke(final byte[] pkhash, final byte[] sig);
}
