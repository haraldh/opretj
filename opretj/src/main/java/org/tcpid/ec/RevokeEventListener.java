package org.tcpid.ec;

public interface RevokeEventListener {
    void onRevoke(MasterVerifyKey key);
}
