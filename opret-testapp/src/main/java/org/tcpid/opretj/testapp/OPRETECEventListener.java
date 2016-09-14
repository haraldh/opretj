package org.tcpid.opretj.testapp;

import org.tcpid.key.MasterVerifyKey;

public interface OPRETECEventListener {
    void onOPRETRevoke(MasterVerifyKey key);
}
