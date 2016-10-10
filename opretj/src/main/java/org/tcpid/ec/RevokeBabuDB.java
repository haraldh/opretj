package org.tcpid.ec;

import java.util.concurrent.CopyOnWriteArrayList;

import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import org.tcpid.opretj.ChangeEventListener;
import org.xtreemfs.babudb.BabuDBFactory;
import org.xtreemfs.babudb.api.BabuDB;
import org.xtreemfs.babudb.api.database.Database;
import org.xtreemfs.babudb.api.exception.BabuDBException;
import org.xtreemfs.babudb.config.ConfigBuilder;

import com.google.common.primitives.Bytes;

public class RevokeBabuDB implements RevokeDBInterface {
    private static final int INDEX_REVOKED = 0;
    private static final int INDEX_SIGNATURE = 1;
    private static final int INDEX_CHECK = 2;
    private final CopyOnWriteArrayList<ListenerRegistration<RevokeEventListener>> revokeEventListeners = new CopyOnWriteArrayList<>();

    private final Database db;
    
    public RevokeBabuDB(String baseDir) throws Exception {
        final BabuDB databaseSystem = BabuDBFactory.createBabuDB(new ConfigBuilder().setDataPath(baseDir).build());

        Database d;
        try {
            d = databaseSystem.getDatabaseManager().getDatabase("revoke");
        } catch (final BabuDBException e) {
            d = databaseSystem.getDatabaseManager().createDatabase("revoke", 3);
        }
        db = d;
    }

    @Override
    public void addRevokeEventListener(final RevokeEventListener listener) {
        // This is thread safe, so we don't need to take the lock.
        revokeEventListeners.add(new ListenerRegistration<RevokeEventListener>(listener, Threading.SAME_THREAD));
    }
    
    protected void queueOnRevoke(final MasterVerifyKey key) {
        for (final ListenerRegistration<RevokeEventListener> registration : revokeEventListeners) {
            registration.executor.execute(() -> registration.listener.onRevoke(key));
        }
    }

    @Override
    public boolean removeRevokeEventListener(final RevokeEventListener listener) {
        return ListenerRegistration.removeFromList(listener, revokeEventListeners);
    }

    @Override
    public boolean isRevoked(MasterVerifyKey key) {
        try {
            byte[] result = db.lookup(INDEX_REVOKED, key.toHash(), null).get();
            return (result != null);
        } catch (BabuDBException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean storeForCheck(MasterVerifyKey key) {
        if (isRevoked(key)) {
            return false;
        }
        // TODO: check all INDEX_SIGNATURE with shortkeyhash and check the signature
        // insert as Revoked, if verified
        
        try {
            db.singleInsert(INDEX_CHECK, key.toHash(), key.toBytes(), null).get();
            return true;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public MasterVerifyKey checkAndStoreKeySignature(byte[] shortkeyhash, byte[] txhash, byte[] signature) {

        // TODO: get all INDEX_CHECK keys starting with shortkeyhash and check the signature
        // and if verified, return MasterVerifyKey
        
        byte[] key = Bytes.concat(shortkeyhash, txhash);

        try {
            db.singleInsert(INDEX_SIGNATURE, key, signature, null).get();
            return null;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean storeRevoke(MasterVerifyKey key, byte[] signature) {
        try {
            // remove key from checked index
            db.singleInsert(INDEX_CHECK, key.toHash(), null, null).get();
            // mark key as revoked
            db.singleInsert(INDEX_REVOKED, key.toHash(), signature, null).get();
            return true;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }
}
