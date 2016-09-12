package org.tcpid.opretj;

import org.tcpid.key.MasterVerifyKey;

public interface OPRETECEventListener {
    void onOPRETRevoke(MasterVerifyKey key);
}
