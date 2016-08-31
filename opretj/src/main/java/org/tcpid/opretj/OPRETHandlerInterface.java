package org.tcpid.opretj;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

import org.bitcoinj.core.PartialMerkleTree;
import org.bitcoinj.core.Sha256Hash;

public interface OPRETHandlerInterface {

    void addOPRET(byte[] magic, long earliestTime);

    void addOPRETChangeEventListener(Executor executor, OPRETChangeEventListener listener);

    long getEarliestElementCreationTime();

    int getOPRETCount();

    Set<List<Byte>> getOPRETSet();

    void pushData(final Sha256Hash h, final Sha256Hash sha256Hash, final Set<Sha256Hash> txprev,
            final List<List<Byte>> myList);

    void pushMerkle(final Sha256Hash sha256Hash, final PartialMerkleTree partialMerkleTree);

    void removeOPRET(byte[] magic);

    boolean removeOPRETChangeEventListener(OPRETChangeEventListener listener);

}
