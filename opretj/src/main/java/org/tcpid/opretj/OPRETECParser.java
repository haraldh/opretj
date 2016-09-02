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
    private static final List<Byte> OPRET_MAGIC = Bytes.asList(Utils.HEX.decode("ec0f"));
    protected final Map<Sha256Hash, PartialMerkleTree> merkleHashMap = new HashMap<>();
    protected final Map<Sha256Hash, OPRETTransaction> transHashMap = new HashMap<>();
    private final CopyOnWriteArrayList<ListenerRegistration<OPRETECEventListener>> opReturnChangeListeners = new CopyOnWriteArrayList<>();

    /**
     * Adds an event listener object. Methods on this object are called when
     * scripts watched by this wallet change. The listener is executed by the
     * given executor.
     */
    public void addOPRETECRevokeEventListener(final OPRETECEventListener listener) {
        // This is thread safe, so we don't need to take the lock.
        opReturnChangeListeners.add(new ListenerRegistration<OPRETECEventListener>(listener, Threading.SAME_THREAD));
    }

    private boolean checkData(final OPRETTransaction t) {
        final List<List<Byte>> opret_data = new ArrayList<>(t.opretData);
        logger.debug("checking {}", opret_data);

        if (opret_data.size() != 3) {
            return false;
        }

        List<Byte> chunk;
        chunk = opret_data.get(0);
        if (!chunk.equals(OPRET_MAGIC)) {
            logger.debug("chunk 0: != OPRET_MAGIC");
            return false;
        }

        chunk = opret_data.get(1);
        if ((chunk.size() != 64)) {
            logger.debug("chunk 1 size != 64, but {}", chunk.size());
            return false;
        }

        chunk = opret_data.get(2);
        if ((chunk.size() != 12)) {
            logger.debug("chunk 2 size!= 12 but {} ", chunk.size());
            return false;
        }

        return handleRevoke(t);

    }

    private boolean handleRevoke(final OPRETTransaction t) {
        final byte[] pkhash = Bytes.toArray(t.opretData.get(2));
        final byte[] sig = Bytes.toArray(t.opretData.get(1));

        logger.debug("REVOKE PK {} - SIG {}", Utils.HEX.encode(pkhash), Utils.HEX.encode(sig));
        queueOnOPRETRevoke(pkhash, sig);
        return true;
    }

    @Override
    public void pushData(final Sha256Hash blockHash, final Sha256Hash txHash, final Set<Sha256Hash> txPrevHash,
            final List<List<Byte>> opret_data) {
        checkData(new OPRETTransaction(blockHash, txHash, opret_data));
    }

    @Override
    public void pushMerkle(final Sha256Hash blockHash, final PartialMerkleTree partialMerkleTree) {
        merkleHashMap.put(blockHash, partialMerkleTree);
        logger.info("block hash {}", blockHash);
        logger.info("Merkle Tree: {}", partialMerkleTree);
    }

    protected void queueOnOPRETRevoke(final byte[] pkhash, final byte[] sig) {
        for (final ListenerRegistration<OPRETECEventListener> registration : opReturnChangeListeners) {
            registration.executor.execute(() -> registration.listener.onOPRETRevoke(pkhash, sig));
        }
    }

    /**
     * Removes the given event listener object. Returns true if the listener was
     * removed, false if that listener was never added.
     */
    public boolean removeOPRETECRevokeEventListener(final OPRETECEventListener listener) {
        return ListenerRegistration.removeFromList(listener, opReturnChangeListeners);
    }
}
