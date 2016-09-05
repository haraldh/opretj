package org.tcpid.opretj;

import org.tcpid.key.VerifyKey;

public interface OPRETECEventListener {
    void onOPRETRevoke(VerifyKey key);
}
