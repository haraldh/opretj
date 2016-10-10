package org.tcpid.opretj;

import java.util.List;

import org.bitcoinj.core.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

public class SimpleLogger extends BaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(SimpleLogger.class);

    @Override
    public void pushTransaction(final Transaction t) {
        final StringBuilder buf = new StringBuilder();

        for (final List<Byte> d : t.opretData) {
            buf.append(Utils.HEX.encode(Bytes.toArray(d)));
            buf.append(" ");
        }

        logger.info("Received in Block: {}\nTX: {}\nData: {}", t.blockHash, t.txHash, buf);
    }

}