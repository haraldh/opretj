package org.tcpid.opretj;


import java.util.List;
import java.util.Set;

import org.bitcoinj.core.PartialMerkleTree;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

public class OPRETSimpleLogger extends OPRETBaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(OPRETSimpleLogger.class);

    @Override
    public void pushData(final Sha256Hash blockHash, final Sha256Hash txHash, final Set<Sha256Hash> txPrevHash,
            final List<List<Byte>> opret_data) {
        final StringBuilder buf = new StringBuilder();
        final StringBuilder bufPrev = new StringBuilder();

        for (final List<Byte> d : opret_data) {
            buf.append(Utils.HEX.encode(Bytes.toArray(d)));
            buf.append(" ");
        }

        for (final Sha256Hash d : txPrevHash) {
            bufPrev.append(d.toString());
            bufPrev.append(" ");
        }
        logger.info("Received in Block: {}\nTX: {}\nTxPrev: {}\nData: {}", blockHash, txHash, bufPrev, buf);
    }

    @Override
    public void pushMerkle(final Sha256Hash blockHash, final PartialMerkleTree partialMerkleTree) {
        logger.info("block hash {}", blockHash);
        logger.info("Merkle Tree: {}", partialMerkleTree);
    }
}
