package org.tcpid.opretj;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

public interface OPRETHandlerInterface {

    // void addOPRET(byte[] magic, long earliestTime);

    void addOPRETChangeEventListener(Executor executor, OPRETChangeEventListener listener);

    long getEarliestElementCreationTime();

    int getOPRETCount();

    Set<List<Byte>> getOPRETSet();

    // void removeOPRET(byte[] magic);

    void pushTransaction(OPRETTransaction t);

    boolean removeOPRETChangeEventListener(OPRETChangeEventListener listener);

}
