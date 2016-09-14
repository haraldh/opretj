package org.tcpid.opret;

import org.tcpid.key.MasterVerifyKey;

public interface OPRETECEventListener {
    void onOPRETRevoke(MasterVerifyKey key);
}
