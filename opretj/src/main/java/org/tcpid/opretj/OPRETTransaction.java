package org.tcpid.opretj;


import java.io.Serializable;
import java.util.List;
import java.util.Set;

import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;

import com.google.common.primitives.Bytes;

public class OPRETTransaction implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 4234625243756902517L;
    public final Sha256Hash blockHash;
    public final Sha256Hash txHash;
    public final Set<Sha256Hash> txPrevHash;
    public final List<List<Byte>> opretData;

    public OPRETTransaction(final Sha256Hash blockHash, final Sha256Hash txHash, final Set<Sha256Hash> txPrevHash,
            final List<List<Byte>> opret_data) {
        this.blockHash = blockHash;
        this.txHash = txHash;
        this.txPrevHash = txPrevHash;
        this.opretData = opret_data;
    }

    @Override
    public String toString() {
        final StringBuilder buf = new StringBuilder();
        buf.append("Received in Block: ").append(blockHash).append("\n");
        buf.append("TX: ").append(txHash).append("\n");
        buf.append("TxPrev: ");

        for (final Sha256Hash d : txPrevHash) {
            buf.append(d.toString());
            buf.append(" ");
        }
        buf.append("\n");
        buf.append("Data: ");
        for (final List<Byte> d : opretData) {
            buf.append(Utils.HEX.encode(Bytes.toArray(d)));
            buf.append(" ");
        }
        return buf.toString();
    }
}
