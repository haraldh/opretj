package org.tcpid.opretj;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

public interface OPRETHandlerInterface {

    void addOPRETChangeEventListener(Executor executor, OPRETChangeEventListener listener);

    long getEarliestElementCreationTime();

    int getOPRETCount();

    Set<List<Byte>> getOPRETSet();

    boolean removeOPRETChangeEventListener(OPRETChangeEventListener listener);

    void pushTransactions(List<OPRETTransaction> pushlist);

}
