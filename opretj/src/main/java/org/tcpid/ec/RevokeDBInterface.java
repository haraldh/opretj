package org.tcpid.ec;


public interface RevokeDBInterface {
    public void addRevokeEventListener(final RevokeEventListener listener);
    public boolean removeRevokeEventListener(final RevokeEventListener listener);
    boolean isRevoked(MasterVerifyKey key);
    boolean storeForCheck(MasterVerifyKey key);
    MasterVerifyKey checkAndStoreKeySignature(byte[] shortkeyhash, byte[] txhash, byte[] signature);
    boolean storeRevoke(MasterVerifyKey key, byte[] signature);
}
