package org.tcpid.opretj;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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
import org.bitcoinj.core.TransactionInput;
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

    private final Set<Sha256Hash> blocksToStore = new HashSet<>();
    protected final Map<Sha256Hash, Transaction> pendingTransactions;

    public OPRETWallet(final NetworkParameters params, final KeyChainGroup keyChainGroup,
            final OPRETHandlerInterface bs) {
        super(params, keyChainGroup);
        opbs = bs;
        pendingTransactions = new HashMap<Sha256Hash, Transaction>();
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
        if (!blocksToStore.contains(block.getHash())) {
            return;
        }

        opbs.pushMerkle(block.getHash(), filteredBlock.getPartialMerkleTree());

        blocksToStore.remove(block.getHash());
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

        final Set<Sha256Hash> txprev = new HashSet<>();

        for (final TransactionInput in : tx.getInputs()) {
            try {
                final Transaction t = pendingTransactions.get(in.getOutpoint().getHash());
                txprev.add(t.getHash());
                pendingTransactions.remove(t);
            } catch (final Exception e) {
                ;
            }
        }

        pendingTransactions.put(tx.getHash(), tx);

        final Sha256Hash h = block.getHeader().getHash();
        if (!blocksToStore.contains(h)) {
            blocksToStore.add(h);
        }

        opbs.pushData(h, tx.getHash(), txprev, myList);
    }
}
