package org.tcpid.opretj;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

public interface HandlerInterface {

    // void addOPRET(byte[] magic, long earliestTime);

    void addOPRETChangeEventListener(Executor executor, ChangeEventListener listener);

    long getEarliestElementCreationTime();

    int getOPRETCount();

    Set<List<Byte>> getOPRETSet();

    // void removeOPRET(byte[] magic);

    void pushTransaction(Transaction t);

    boolean removeOPRETChangeEventListener(ChangeEventListener listener);

}
