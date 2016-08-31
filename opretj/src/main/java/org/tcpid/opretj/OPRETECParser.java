package org.tcpid.opretj;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import org.bitcoinj.core.PartialMerkleTree;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

public class OPRETECParser extends OPRETBaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(OPRETECParser.class);
    private static final List<Byte> OPRET_MAGIC = Bytes.asList(Utils.HEX.decode("ec1d"));
    protected final Map<Sha256Hash, PartialMerkleTree> merkleHashMap = new HashMap<>();
    protected final Map<Sha256Hash, OPRETTransaction> transHashMap = new HashMap<>();
    private final CopyOnWriteArrayList<ListenerRegistration<OPRETECRevokeEventListener>> opReturnChangeListeners = new CopyOnWriteArrayList<>();

    /**
     * Adds an event listener object. Methods on this object are called when
     * scripts watched by this wallet change. The listener is executed by the
     * given executor.
     */
    public void addOPRETECRevokeEventListener(final OPRETECRevokeEventListener listener) {
        // This is thread safe, so we don't need to take the lock.
        opReturnChangeListeners
                .add(new ListenerRegistration<OPRETECRevokeEventListener>(listener, Threading.USER_THREAD));
    }

    private boolean checkData(final OPRETTransaction t1, final OPRETTransaction t2) {
        final List<List<Byte>> opret_data = new ArrayList<>(t1.opretData);
        opret_data.addAll(t2.opretData);
        logger.debug("checking {}", opret_data);

        List<Byte> chunk;
        chunk = opret_data.get(0);
        if (!chunk.equals(OPRET_MAGIC)) {
            logger.debug("0: != OPRET_MAGIC");
            return false;
        }

        chunk = opret_data.get(1);
        if (chunk.size() != 1) {
            logger.debug("1: size != 1");
            return false;
        }

        if (chunk.get(0) == (byte) 0xFE) {
            if (opret_data.size() != 8) {
                logger.debug("FE: size != 8");
                return false;
            }
            chunk = opret_data.get(4);
            if (!chunk.equals(OPRET_MAGIC)) {
                logger.debug("FE 4 != OPRET_MAGIC");
                return false;
            }
            if (!opret_data.get(2).equals(opret_data.get(6))) {
                logger.debug("FE 2 != 6");
                return false;
            }
            chunk = opret_data.get(5);
            if ((chunk.size() != 1) || (chunk.get(0) != (byte) 0xFF)) {
                logger.debug("FE 5 size!=1 or != FF");
                return false;
            }

            return handleRevoke(t1, t2);
        } else {
            logger.debug("1: != 0xFE");
        }

        return false;
    }

    private boolean handleRevoke(final OPRETTransaction t1, final OPRETTransaction t2) {
        final byte[] pkhash = Bytes.toArray(t1.opretData.get(2));
        final byte[] sig = Bytes.concat(Bytes.toArray(t1.opretData.get(3)), Bytes.toArray(t2.opretData.get(3)));

        logger.debug("REVOKE PK {} - SIG {}", Utils.HEX.encode(pkhash), Utils.HEX.encode(sig));
        queueOnOPRETRevoke(pkhash, sig);
        return true;
    }

    @Override
    public void pushData(final Sha256Hash blockHash, final Sha256Hash txHash, final Set<Sha256Hash> txPrevHash,
            final List<List<Byte>> opret_data) {
        final OPRETTransaction optrans = new OPRETTransaction(blockHash, txHash, txPrevHash, opret_data);
        logger.debug("pushData: {}", optrans);
        for (final Sha256Hash t : txPrevHash) {
            if (transHashMap.containsKey(t)) {
                final OPRETTransaction opprev = transHashMap.get(t);
                if (checkData(opprev, optrans)) {
                    transHashMap.remove(t);
                    return;
                }
            }
        }
        transHashMap.put(txHash, optrans);
    }

    @Override
    public void pushMerkle(final Sha256Hash blockHash, final PartialMerkleTree partialMerkleTree) {
        merkleHashMap.put(blockHash, partialMerkleTree);
        logger.info("block hash {}", blockHash);
        logger.info("Merkle Tree: {}", partialMerkleTree);
    }

    protected void queueOnOPRETRevoke(final byte[] pkhash, final byte[] sig) {
        for (final ListenerRegistration<OPRETECRevokeEventListener> registration : opReturnChangeListeners) {
            registration.executor.execute(() -> registration.listener.onOPRETRevoke(pkhash, sig));
        }
    }

    /**
     * Removes the given event listener object. Returns true if the listener was
     * removed, false if that listener was never added.
     */
    public boolean removeOPRETECRevokeEventListener(final OPRETECRevokeEventListener listener) {
        return ListenerRegistration.removeFromList(listener, opReturnChangeListeners);
    }
}
