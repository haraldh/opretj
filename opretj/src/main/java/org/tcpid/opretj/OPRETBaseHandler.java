package org.tcpid.opretj;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;

import org.bitcoinj.core.Utils;
import org.bitcoinj.utils.ListenerRegistration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

public abstract class OPRETBaseHandler implements OPRETHandlerInterface {
    private static final Logger logger = LoggerFactory.getLogger(OPRETBaseHandler.class);
    private final CopyOnWriteArrayList<ListenerRegistration<OPRETChangeEventListener>> opReturnChangeListeners = new CopyOnWriteArrayList<ListenerRegistration<OPRETChangeEventListener>>();
    private final Map<List<Byte>, Long> magicBytes = new HashMap<>();

    @Override
    public void addOPRET(final byte[] magic, final long earliestTime) {
        logger.debug("addMagicBytes: {} - Time {}", Utils.HEX.encode(magic), earliestTime);
        final List<Byte> blist = Bytes.asList(magic);
        magicBytes.put(blist, earliestTime);
        queueOnOPRETChanged();
    }

    /**
     * Adds an event listener object. Methods on this object are called when
     * scripts watched by this wallet change. The listener is executed by the
     * given executor.
     */
    @Override
    public void addOPRETChangeEventListener(final Executor executor, final OPRETChangeEventListener listener) {
        // This is thread safe, so we don't need to take the lock.
        opReturnChangeListeners.add(new ListenerRegistration<OPRETChangeEventListener>(listener, executor));
    }

    @Override
    public long getEarliestElementCreationTime() {
        long earliestTime = Long.MAX_VALUE;

        for (Long t : magicBytes.values()) {
            if (t == Long.MAX_VALUE) {
                t = Utils.currentTimeSeconds();
            }
            earliestTime = Math.min(t, earliestTime);
        }

        return earliestTime;
    }

    @Override
    public int getOPRETCount() {
        return magicBytes.size();
    }

    @Override
    public Set<List<Byte>> getOPRETSet() {
        return magicBytes.keySet();
    }

    protected void queueOnOPRETChanged() {
        for (final ListenerRegistration<OPRETChangeEventListener> registration : opReturnChangeListeners) {
            registration.executor.execute(() -> registration.listener.onOPRETChanged());
        }
    }

    @Override
    public void removeOPRET(final byte[] magic) {
        magicBytes.remove(Bytes.asList(magic));
        queueOnOPRETChanged();
    }

    /**
     * Removes the given event listener object. Returns true if the listener was
     * removed, false if that listener was never added.
     */
    @Override
    public boolean removeOPRETChangeEventListener(final OPRETChangeEventListener listener) {
        return ListenerRegistration.removeFromList(listener, opReturnChangeListeners);
    }

}
