package org.tcpid.opretj;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;
import static org.libsodium.jni.SodiumConstants.NONCE_BYTES;
import static org.libsodium.jni.SodiumConstants.SECRETKEY_BYTES;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.bitcoinj.core.PartialMerkleTree;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.utils.ListenerRegistration;
import org.bitcoinj.utils.Threading;
import org.libsodium.jni.crypto.Hash;
import org.libsodium.jni.crypto.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.HMACSHA512256;
import org.tcpid.key.MasterSigningKey;
import org.tcpid.key.SigningKey;
import org.tcpid.key.VerifyKey;

import com.google.common.primitives.Bytes;

public class OPRETECParser extends OPRETBaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(OPRETECParser.class);
    public static final Hash HASH = new Hash();

    private static final List<Byte> OPRET_MAGIC = Bytes.asList(Utils.HEX.decode("ec0f"));

    public static boolean checkKeyforRevoke(final VerifyKey k, final byte[] sig) {
        logger.debug("CHECKING REVOKE PKHASH {} - SIG {}", Utils.HEX.encode(k.toHash()), Utils.HEX.encode(sig));

        final byte[] revokemsg = Bytes.concat("Revoke ".getBytes(), k.toHash());

        logger.debug("Using VerifyKey {}", k);

        if (k.verify(revokemsg, sig)) {
            logger.debug("REVOKED VerifyKey {}", k);
            return true;
        } else {
            logger.debug("SIGNATURE does not match!");
            return false;
        }
    }

    public static Script getRevokeScript(final SigningKey key) {
        final byte[] revokemsg = Bytes.concat("Revoke ".getBytes(), key.getVerifyKey().toHash());
        final byte[] sig = key.sign(revokemsg);

        final Script script = new ScriptBuilder().op(OP_RETURN).data(Utils.HEX.decode("ec0f")).data(sig)
                .data(key.getVerifyKey().getShortHash()).build();
        return script;
    }

    protected final Map<Sha256Hash, PartialMerkleTree> merkleHashMap = Collections.synchronizedMap(new HashMap<>());

    protected final Map<Sha256Hash, OPRETTransaction> transHashMap = Collections.synchronizedMap(new HashMap<>());

    protected final Map<List<Byte>, List<VerifyKey>> verifyKeys = Collections.synchronizedMap(new HashMap<>());

    private final CopyOnWriteArrayList<ListenerRegistration<OPRETECEventListener>> opReturnChangeListeners = new CopyOnWriteArrayList<>();

    /**
     * Adds an event listener object. Methods on this object are called when
     * scripts watched by this wallet change. The listener is executed by the
     * given executor.
     */
    public void addOPRETECRevokeEventListener(final OPRETECEventListener listener) {
        // This is thread safe, so we don't need to take the lock.
        opReturnChangeListeners.add(new ListenerRegistration<OPRETECEventListener>(listener, Threading.SAME_THREAD));
    }

    public void addVerifyKey(final VerifyKey key, final long earliestTime) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());
        if (!verifyKeys.containsKey(hash)) {
            verifyKeys.put(hash, new ArrayList<VerifyKey>());
        }

        verifyKeys.get(hash).add(key);
        logger.debug("Adding pkhash {}", key.getShortHash());
        addOPRET(key.getShortHash(), earliestTime);
    }

    private boolean checkData(final OPRETTransaction t) {
        final List<List<Byte>> opret_data = new ArrayList<>(t.opretData);
        logger.debug("checking {}", opret_data);

        if (opret_data.size() != 3) {
            return false;
        }

        List<Byte> chunk;
        chunk = opret_data.get(0);
        if (!chunk.equals(OPRET_MAGIC)) {
            logger.debug("chunk 0: != OPRET_MAGIC");
            return false;
        }

        chunk = opret_data.get(1);
        if ((chunk.size() != 64)) {
            logger.debug("chunk 1 size != 64, but {}", chunk.size());
            return false;
        }

        chunk = opret_data.get(2);
        if ((chunk.size() != 12)) {
            logger.debug("chunk 2 size!= 12 but {} ", chunk.size());
            return false;
        }

        return handleRevoke(t);
    }

    public boolean cryptoSelfTest() {
        if (NONCE_BYTES > HMACSHA512256.HMACSHA512256_BYTES) {
            logger.error("NONCE_BYTES > HMACSHA512256.HMACSHA512256_BYTES: {} > {}", NONCE_BYTES,
                    HMACSHA512256.HMACSHA512256_BYTES);
            return false;
        }

        if (SECRETKEY_BYTES != HMACSHA512256.HMACSHA512256_BYTES) {
            logger.error("SECRETKEY_BYTES != HMACSHA512256.HMACSHA512256_BYTES: {} > {}", SECRETKEY_BYTES,
                    HMACSHA512256.HMACSHA512256_BYTES);
            return false;
        }

        final MasterSigningKey msk = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));
        if (!Arrays.equals(Utils.HEX.decode("4071b2b3db7cc7aecd0b23608e96f44f08463ea0ee0a0c12f5fa21ff449deb55"),
                msk.toBytes())) {
            logger.error("MasterSigningKey(HASH.sha256('TESTSEED'.getBytes())) test failed");
            return false;
        }
        final MasterSigningKey subkey = msk.getSubKey(1L).getSubKey(2L).getSubKey(3L).getSubKey(4L);
        if (!Arrays.equals(Utils.HEX.decode("00cb0c8748318d27eab65159a2261c028d764c1154fc302b9b046aa2bbefab27"),
                subkey.toBytes())) {
            logger.error("MasterSigningKey subkey derivation failed");
            return false;
        }
        final BigInteger biMSK = new BigInteger(1, msk.toBytes());
        BigInteger biSub = new BigInteger(1, subkey.toBytes());
        final BigInteger pow2_256 = new BigInteger("10000000000000000000000000000000000000000000000000000000000000000",
                16);
        final BigInteger biDiff = biSub.subtract(biMSK).mod(pow2_256);

        logger.debug("{} = {}", Utils.HEX.encode(msk.toBytes()), biMSK.toString(16));

        logger.debug("{} - {} = {}", Utils.HEX.encode(msk.toBytes()), Utils.HEX.encode(subkey.toBytes()),
                Utils.HEX.encode(biDiff.toByteArray()));

        biSub = biMSK.add(biDiff).mod(pow2_256);
        final byte[] bisubb = biSub.toByteArray();
        logger.debug("{}", Utils.HEX.encode(Util.prependZeros(32 - bisubb.length, bisubb)));

        if (!Arrays.equals(bisubb, subkey.toBytes())) {
            logger.error("MasterSigningKey subkey difference calculation failed");
            return false;
        }

        return true;
    }

    private boolean handleRevoke(final OPRETTransaction t) {
        final List<Byte> pkhash = t.opretData.get(2);
        final byte[] sig = Bytes.toArray(t.opretData.get(1));
        if (!verifyKeys.containsKey(pkhash)) {
            return false;
        }

        for (final VerifyKey k : verifyKeys.get(t.opretData.get(2))) {
            if (checkKeyforRevoke(k, sig)) {
                if (k.isRevoked()) {
                    logger.debug("Duplicate REVOKE PK {} - SIG {}", Utils.HEX.encode(k.getShortHash()),
                            Utils.HEX.encode(sig));
                } else {
                    k.setRevoked(true);
                    logger.debug("REVOKE PK {} - SIG {}", Utils.HEX.encode(k.getShortHash()), Utils.HEX.encode(sig));
                }
                queueOnOPRETRevoke(k);
                return true;

            }
        }
        return false;
    }

    @Override
    public void pushTransaction(final OPRETTransaction t) {
        checkData(t);
    }

    protected void queueOnOPRETRevoke(final VerifyKey key) {
        for (final ListenerRegistration<OPRETECEventListener> registration : opReturnChangeListeners) {
            registration.executor.execute(() -> registration.listener.onOPRETRevoke(key));
        }
    }

    /**
     * Removes the given event listener object. Returns true if the listener was
     * removed, false if that listener was never added.
     */
    public boolean removeOPRETECRevokeEventListener(final OPRETECEventListener listener) {
        return ListenerRegistration.removeFromList(listener, opReturnChangeListeners);
    }

    public void removeVerifyKey(final VerifyKey key) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());

        if (!verifyKeys.containsKey(hash)) {
            return;
        }

        verifyKeys.get(hash).remove(key);

        removeOPRET(key.getShortHash());
    }
}
