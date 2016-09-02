package org.tcpid.opretj;

import java.io.Serializable;
import java.util.List;

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
    public final List<List<Byte>> opretData;

    public OPRETTransaction(final Sha256Hash blockHash, final Sha256Hash txHash, final List<List<Byte>> opret_data) {
        this.blockHash = blockHash;
        this.txHash = txHash;
        this.opretData = opret_data;
    }

    @Override
    public String toString() {
        final StringBuilder buf = new StringBuilder();
        buf.append("Received in Block: ").append(blockHash).append("\n");
        buf.append("TX: ").append(txHash).append("\n");
        buf.append("Data: ");
        for (final List<Byte> d : opretData) {
            buf.append(Utils.HEX.encode(Bytes.toArray(d)));
            buf.append(" ");
        }
        return buf.toString();
    }
}
