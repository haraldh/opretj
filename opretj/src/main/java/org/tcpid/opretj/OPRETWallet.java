package org.tcpid.opretj;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.FilteredBlock;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.listeners.BlocksDownloadedEventListener;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

public class OPRETWallet extends Wallet implements BlocksDownloadedEventListener, OPRETChangeEventListener {

    private final OPRETHandlerInterface opbs;
    private final Logger logger = LoggerFactory.getLogger(OPRETWallet.class);

    protected final Map<Sha256Hash, Map<Sha256Hash, OPRETTransaction>> pendingTransactions = Collections
            .synchronizedMap(new HashMap<>());

    public OPRETWallet(final NetworkParameters params, final KeyChainGroup keyChainGroup,
            final OPRETHandlerInterface bs) {
        super(params, keyChainGroup);
        opbs = bs;
    }

    @Override
    public BloomFilter getBloomFilter(final int size, final double falsePositiveRate, final long nTweak) {
        beginBloomFilterCalculation();
        try {
            final BloomFilter filter = super.getBloomFilter(size, falsePositiveRate, nTweak);
            for (final List<Byte> magic : opbs.getOPRETSet()) {
                logger.debug("Magic add bloom: {}", Utils.HEX.encode(Bytes.toArray(magic)));
                filter.insert(Bytes.toArray(magic));
            }
            return filter;
        } finally {
            endBloomFilterCalculation();
        }
    }

    @Override
    public int getBloomFilterElementCount() {
        beginBloomFilterCalculation();
        try {
            logger.debug("Magic Bytes Size: {}", opbs.getOPRETCount());
            return super.getBloomFilterElementCount() + opbs.getOPRETCount();
        } finally {
            endBloomFilterCalculation();
        }
    }

    @Override
    public long getEarliestKeyCreationTime() {
        long earliestTime = opbs.getEarliestElementCreationTime();

        if (earliestTime == Long.MAX_VALUE) {
            earliestTime = Utils.currentTimeSeconds();
        }

        return Math.min(super.getEarliestKeyCreationTime(), earliestTime);
    }

    @Override
    public boolean isPendingTransactionRelevant(final Transaction tx) throws ScriptException {
        logger.debug("isPendingTransactionRelevant {}", tx.getHashAsString());

        if (pendingTransactions.containsValue(tx)) {
            return true;
        }

        if (isTransactionOPReturn(tx) != null) {
            return true;
        }

        return false;
    }

    public List<List<Byte>> isTransactionOPReturn(final Transaction tx) throws ScriptException {
        final Set<List<Byte>> magicBytes = opbs.getOPRETSet();
        final List<List<Byte>> myList = new ArrayList<>();

        for (final TransactionOutput out : tx.getOutputs()) {
            final Script script = out.getScriptPubKey();
            final List<ScriptChunk> chunks = script.getChunks();
            if (chunks.size() == 0) {
                continue;
            }

            if (!chunks.get(0).equalsOpCode(OP_RETURN)) {
                continue;
            }
            boolean found = false;

            for (final ScriptChunk chunk : chunks) {
                if (chunk.data == null) {
                    continue;
                }
                final List<Byte> magic = Bytes.asList(chunk.data);

                if (chunk.equalsOpCode(OP_RETURN)) {
                    continue;
                } else {
                    myList.add(magic);
                }

                if (magicBytes.contains(magic)) {
                    found = true;
                }
            }
            if (found == true) {
                return myList;
            }
            return null;
        }

        return null;
    }

    @Override
    public void onBlocksDownloaded(final Peer peer, final Block block, final FilteredBlock filteredBlock,
            final int blocksLeft) {
        final ArrayList<OPRETTransaction> pushlist = new ArrayList<>();

        if (!pendingTransactions.containsKey(block.getHash())) {
            return;
        }

        for (final OPRETTransaction t : pendingTransactions.get(block.getHash()).values()) {
            t.setPartialMerkleTree(filteredBlock.getPartialMerkleTree());
            t.setTime(block.getTime());
            pushlist.add(t);
        }

        if (!pushlist.isEmpty()) {
            opbs.pushTransactions(pushlist);
        }

        pendingTransactions.remove(block.getHash());
    }

    @Override
    public void onOPRETChanged() {
        queueOnScriptsChanged(null, false);
    }

    @Override
    public void receiveFromBlock(final Transaction tx, final StoredBlock block, final BlockChain.NewBlockType blockType,
            final int relativityOffset) throws VerificationException {

        super.receiveFromBlock(tx, block, blockType, relativityOffset);

        final List<List<Byte>> myList = isTransactionOPReturn(tx);

        if (myList == null) {
            logger.debug("False Positive Transaction {}", tx.toString());
            return;
        }
        logger.debug("Found Transaction {}", tx.toString());
        final Sha256Hash h = block.getHeader().getHash();

        if (!pendingTransactions.containsKey(h)) {
            pendingTransactions.put(h, Collections.synchronizedMap(new HashMap<Sha256Hash, OPRETTransaction>()));
        }

        pendingTransactions.get(h).put(tx.getHash(), new OPRETTransaction(h, tx.getHash(), myList));

    }
}
