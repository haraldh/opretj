package org.tcpid.opretj.testapp;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;
import static org.libsodium.jni.NaCl.sodium;
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
import org.libsodium.jni.Sodium;
import org.libsodium.jni.crypto.Hash;
import org.libsodium.jni.crypto.Util;
import org.libsodium.jni.encoders.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.HMACSHA512256;
import org.tcpid.key.MasterSigningKey;
import org.tcpid.key.MasterVerifyKey;
import org.tcpid.key.SigningKey;
import org.tcpid.key.VerifyKey;
import org.tcpid.opretj.OPRETBaseHandler;
import org.tcpid.opretj.OPRETTransaction;

import com.google.common.primitives.Bytes;

public class OPRETECParser extends OPRETBaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(OPRETECParser.class);
    public static final Hash HASH = new Hash();

    private static final List<Byte> OPRET_MAGIC_EC1C = Bytes.asList(Utils.HEX.decode("ec1c"));
    private static final List<Byte> OPRET_MAGIC_EC1D = Bytes.asList(Utils.HEX.decode("ec1d"));
    private static final List<Byte> OPRET_MAGIC_ECA1 = Bytes.asList(Utils.HEX.decode("eca1"));
    private static final List<Byte> OPRET_MAGIC_ECA2 = Bytes.asList(Utils.HEX.decode("eca2"));
    private static final List<Byte> OPRET_MAGIC_ECA3 = Bytes.asList(Utils.HEX.decode("eca3"));
    private static final List<Byte> OPRET_MAGIC_ECA4 = Bytes.asList(Utils.HEX.decode("eca4"));
    private static final List<Byte> OPRET_MAGIC_EC51 = Bytes.asList(Utils.HEX.decode("ec51"));
    private static final List<Byte> OPRET_MAGIC_EC52 = Bytes.asList(Utils.HEX.decode("ec52"));
    private static final List<Byte> OPRET_MAGIC_EC0F = Bytes.asList(Utils.HEX.decode("ec0f"));

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
    protected final Map<List<Byte>, List<OPRETTransaction>> transA1HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<OPRETTransaction>> transA2HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<OPRETTransaction>> transA3HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<OPRETTransaction>> transA4HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<OPRETTransaction>> trans51HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<OPRETTransaction>> trans52HashMap = Collections
            .synchronizedMap(new HashMap<>());

    protected final Map<List<Byte>, List<MasterVerifyKey>> verifyKeys = Collections.synchronizedMap(new HashMap<>());

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

    public void addVerifyKey(final MasterVerifyKey key, final long earliestTime) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());
        if (!verifyKeys.containsKey(hash)) {
            verifyKeys.put(hash, new ArrayList<MasterVerifyKey>());
        }

        verifyKeys.get(hash).add(key);
        logger.debug("Adding pkhash {}", key.getShortHash());
        addOPRET(key.getShortHash(), earliestTime);
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

    private boolean handleAnnounce(final OPRETTransaction selfTx,
            final Map<List<Byte>, List<OPRETTransaction>> selfTransHashMap,
            final Map<List<Byte>, List<OPRETTransaction>> otherTransHashMap, final boolean isT1) {

        final byte[] selfData = Bytes.toArray(selfTx.opretData.get(1));
        if (((selfData.length < 48) || (selfData.length > 64))) {
            logger.debug("invalid chunk1 size = {}", selfData.length);
            return false;
        }

        final List<Byte> pkhash = selfTx.opretData.get(2);
        if ((pkhash.size() != 12)) {
            logger.debug("chunk 2 size != 12 but {} ", pkhash.size());
            return false;
        }

        if (!verifyKeys.containsKey(pkhash)) {
            return false;
        }

        if (otherTransHashMap.containsKey(pkhash)) {
            for (final OPRETTransaction otherTx : otherTransHashMap.get(pkhash)) {
                final byte[] otherData = Bytes.toArray(otherTx.opretData.get(1));
                final byte[] cipher = isT1
                        ? Bytes.concat(Arrays.copyOfRange(selfData, 0, 48), Arrays.copyOfRange(otherData, 0, 48))
                        : Bytes.concat(Arrays.copyOfRange(otherData, 0, 48), Arrays.copyOfRange(selfData, 0, 48));
                final BigInteger selfNonce = (selfData.length == 48) ? BigInteger.ZERO
                        : new BigInteger(1, Arrays.copyOfRange(selfData, 48, selfData.length));
                final BigInteger otherNonce = (otherData.length == 48) ? BigInteger.ZERO
                        : new BigInteger(1, Arrays.copyOfRange(otherData, 48, otherData.length));

                final BigInteger nonce = isT1 ? selfNonce.shiftLeft(16 * 8).or(otherNonce)
                        : otherNonce.shiftLeft(16 * 8).or(selfNonce);

                byte[] noncebytes = Util.prependZeros(32, nonce.toByteArray());
                noncebytes = Arrays.copyOfRange(noncebytes, noncebytes.length - 32, noncebytes.length);

                for (final MasterVerifyKey k : verifyKeys.get(pkhash)) {
                    byte[] sharedkey, xornonce;
                    sharedkey = HASH.sha256(HASH.sha256(Bytes.concat(k.toBytes(), noncebytes)));
                    xornonce = Arrays.copyOfRange(HASH.sha256(Bytes.concat(sharedkey, noncebytes)), 0, 24);
                    logger.debug("checking key {}", Encoder.HEX.encode(k.toBytes()));
                    logger.debug("noncebytes {}", Encoder.HEX.encode(noncebytes));
                    logger.debug("noncebytes len {}", noncebytes.length);
                    logger.debug("xornonce {}", Encoder.HEX.encode(xornonce));
                    logger.debug("sharedkey {}", Encoder.HEX.encode(sharedkey));
                    sodium();
                    final byte[] msg = Util.zeros(96);
                    Sodium.crypto_stream_xsalsa20_xor(msg, cipher, 96, xornonce, sharedkey);
                    final byte[] vk = Arrays.copyOfRange(msg, 0, 32);
                    final byte[] sig = Arrays.copyOfRange(msg, 32, 96);
                    try {
                        logger.debug("Checking sig {} with key {}", Encoder.HEX.encode(sig), Encoder.HEX.encode(vk));
                        k.verify(vk, sig);
                    } catch (final RuntimeException e) {
                        logger.debug("sig does not match");
                        continue;
                    }
                    logger.debug("sig matches");

                    k.setFirstValidSubKey(new MasterVerifyKey(vk), selfTx, otherTx);
                    otherTransHashMap.get(pkhash).remove(otherTx);
                    if (otherTransHashMap.get(pkhash).isEmpty()) {
                        otherTransHashMap.remove(pkhash);
                    }
                    return true;
                }
            }
        }

        // no matching transaction found, save for later
        if (!selfTransHashMap.containsKey(pkhash)) {
            selfTransHashMap.put(pkhash, new ArrayList<OPRETTransaction>());
        }
        selfTransHashMap.get(pkhash).add(selfTx);

        return false;
    }

    private boolean handleEC0F(final OPRETTransaction t) {
        final byte[] sig = Bytes.toArray(t.opretData.get(1));
        if ((sig.length != 64)) {
            logger.debug("chunk 1 size != 64, but {}", sig.length);
            return false;
        }

        final List<Byte> pkhash = t.opretData.get(2);
        if ((pkhash.size() != 12)) {
            logger.debug("chunk 2 size!= 12 but {} ", pkhash.size());
            return false;
        }

        if (!verifyKeys.containsKey(pkhash)) {
            return false;
        }

        for (final MasterVerifyKey k : verifyKeys.get(pkhash)) {
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

    private boolean handleEC1C(final OPRETTransaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleEC1D(final OPRETTransaction t) {
        final byte[] sig = Bytes.toArray(t.opretData.get(1));
        if ((sig.length != 64)) {
            logger.debug("chunk 1 size != 64, but {}", sig.length);
            return false;
        }

        final List<Byte> pkhash = t.opretData.get(2);
        if ((pkhash.size() != 12)) {
            logger.debug("chunk 2 size!= 12 but {} ", pkhash.size());
            return false;
        }

        if (!verifyKeys.containsKey(pkhash)) {
            return false;
        }

        for (final MasterVerifyKey k : verifyKeys.get(pkhash)) {
            if (checkKeyforRevoke(k, sig)) {
                if (k.isRevoked()) {
                    logger.debug("Duplicate REVOKE PK {} - SIG {}", Utils.HEX.encode(k.getShortHash()),
                            Utils.HEX.encode(sig));
                } else {
                    k.setRevoked(true);
                    logger.debug("REVOKE PK {} - SIG {}", Utils.HEX.encode(k.getShortHash()), Utils.HEX.encode(sig));
                }
                queueOnOPRETId(k);
                return true;

            }
        }
        return false;
    }

    private boolean handleEC51(final OPRETTransaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleEC52(final OPRETTransaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleECA1(final OPRETTransaction t1) {
        logger.debug("handleECA1");
        return handleAnnounce(t1, transA1HashMap, transA2HashMap, true);
    }

    private boolean handleECA2(final OPRETTransaction t2) {
        logger.debug("handleECA2");
        return handleAnnounce(t2, transA2HashMap, transA1HashMap, false);
    }

    private boolean handleECA3(final OPRETTransaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleECA4(final OPRETTransaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean pushTransaction(final OPRETTransaction t) {
        logger.debug("checking {}", t.opretData);

        if ((t.opretData.size() != 2) && (t.opretData.size() != 3) && (t.opretData.size() != 4)) {
            return false;
        }

        final List<Byte> chunk = t.opretData.get(0);

        if (chunk.equals(OPRET_MAGIC_EC0F)) {
            return handleEC0F(t);
        }

        if (chunk.equals(OPRET_MAGIC_EC1C)) {
            return handleEC1C(t);
        }

        if (chunk.equals(OPRET_MAGIC_EC1D)) {
            return handleEC1D(t);
        }

        if (chunk.equals(OPRET_MAGIC_ECA1)) {
            return handleECA1(t);
        }

        if (chunk.equals(OPRET_MAGIC_ECA2)) {
            return handleECA2(t);
        }

        if (chunk.equals(OPRET_MAGIC_ECA3)) {
            return handleECA3(t);
        }

        if (chunk.equals(OPRET_MAGIC_ECA4)) {
            return handleECA4(t);
        }

        if (chunk.equals(OPRET_MAGIC_EC51)) {
            return handleEC51(t);
        }

        if (chunk.equals(OPRET_MAGIC_EC52)) {
            return handleEC52(t);
        }

        return false;
    }

    private void queueOnOPRETId(final MasterVerifyKey k) {
        // TODO Auto-generated method stub

    }

    protected void queueOnOPRETRevoke(final MasterVerifyKey key) {
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

    public void removeVerifyKey(final MasterVerifyKey key) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());

        if (!verifyKeys.containsKey(hash)) {
            return;
        }

        verifyKeys.get(hash).remove(key);

        removeOPRET(key.getShortHash());
    }
}
