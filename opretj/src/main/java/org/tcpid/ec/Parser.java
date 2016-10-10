package org.tcpid.ec;

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
import org.tcpid.opretj.BaseHandler;
import org.tcpid.opretj.Transaction;

import com.google.common.primitives.Bytes;

public class Parser extends BaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(Parser.class);
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

    private final RevokeDBInterface revokeDB;
    
    public Parser(RevokeDBInterface revokedb) {
        revokeDB = revokedb;
    }
    
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

    protected final Map<Sha256Hash, Transaction> transHashMap = Collections.synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<Transaction>> transA1HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<Transaction>> transA2HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<Transaction>> transA3HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<Transaction>> transA4HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<Transaction>> trans51HashMap = Collections
            .synchronizedMap(new HashMap<>());
    protected final Map<List<Byte>, List<Transaction>> trans52HashMap = Collections
            .synchronizedMap(new HashMap<>());

    protected final Map<List<Byte>, List<MasterVerifyKey>> verifyKeys = Collections.synchronizedMap(new HashMap<>());

    public void addRevokeEventListener(final RevokeEventListener listener) {
        revokeDB.addRevokeEventListener(listener);
    }

    public void addVerifyKey(final MasterVerifyKey key, final long earliestTime) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());
        if (!verifyKeys.containsKey(hash)) {
            verifyKeys.put(hash, new ArrayList<MasterVerifyKey>());
        }

        verifyKeys.get(hash).add(key);
        logger.debug("Adding pkhash {}", key.getShortHash());
        addOPRET(key.getShortHash(), earliestTime);
        revokeDB.storeForCheck(key);
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

    private boolean handleEC0F(final Transaction t) {
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

    private boolean handleEC1C(final Transaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleEC1D(final Transaction t) {
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

    private boolean handleEC51(final Transaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleEC52(final Transaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleECA1(final Transaction t1) {
        // FIXME: refactor with handleECA2

        logger.debug("handleECA1");
        final byte[] data1 = Bytes.toArray(t1.opretData.get(1));
        if (((data1.length < 48) || (data1.length > 64))) {
            logger.debug("invalid chunk1 size = {}", data1.length);
            return false;
        }

        final List<Byte> pkhash = t1.opretData.get(2);
        if ((pkhash.size() != 12)) {
            logger.debug("chunk 2 size != 12 but {} ", pkhash.size());
            return false;
        }

        if (!verifyKeys.containsKey(pkhash)) {
            return false;
        }

        if (transA2HashMap.containsKey(pkhash)) {
            for (final Transaction t2 : transA2HashMap.get(pkhash)) {
                final byte[] data2 = Bytes.toArray(t2.opretData.get(1));
                final byte[] cipher = Bytes.concat(Arrays.copyOfRange(data1, 0, 48), Arrays.copyOfRange(data2, 0, 48));
                BigInteger nonce1 = BigInteger.ZERO;
                BigInteger nonce2 = BigInteger.ZERO;
                if (data1.length > 48) {
                    nonce1 = new BigInteger(1, Arrays.copyOfRange(data1, 48, data1.length));
                    logger.debug("nonce1 {}", Encoder.HEX.encode(nonce1.toByteArray()));
                    logger.debug("nonce1shift {}", Encoder.HEX.encode(nonce1.shiftLeft(16 * 8).toByteArray()));
                }
                if (data2.length > 48) {
                    nonce2 = new BigInteger(1, Arrays.copyOfRange(data2, 48, data2.length));
                    logger.debug("nonce2 {}", Encoder.HEX.encode(nonce2.toByteArray()));
                }

                final BigInteger nonce = nonce1.shiftLeft(16 * 8).or(nonce2);
                logger.debug("nonceshift {}", Encoder.HEX.encode(nonce.toByteArray()));

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

                    k.setFirstValidSubKey(new MasterVerifyKey(vk), t1, t2);
                    transA2HashMap.get(pkhash).remove(t2);
                    if (transA2HashMap.get(pkhash).isEmpty()) {
                        transA2HashMap.remove(pkhash);
                    }
                    return true;
                }
            }
        }
        if (!transA1HashMap.containsKey(pkhash)) {
            transA1HashMap.put(pkhash, new ArrayList<Transaction>());
        }
        transA1HashMap.get(pkhash).add(t1);

        return false;
    }

    private boolean handleECA2(final Transaction t2) {
        // FIXME: refactor with handleECA1
        logger.debug("handleECA2");
        final byte[] data2 = Bytes.toArray(t2.opretData.get(1));
        if (((data2.length < 48) || (data2.length > 64))) {
            logger.debug("invalid chunk1 size = {}", data2.length);
            return false;
        }

        final List<Byte> pkhash = t2.opretData.get(2);
        if ((pkhash.size() != 12)) {
            logger.debug("chunk 2 size != 12 but {} ", pkhash.size());
            return false;
        }

        if (!verifyKeys.containsKey(pkhash)) {
            logger.debug("pkash not in hashmap");
            return false;
        }

        if (transA1HashMap.containsKey(pkhash)) {
            for (final Transaction t1 : transA1HashMap.get(pkhash)) {
                final byte[] data1 = Bytes.toArray(t1.opretData.get(1));
                final byte[] cipher = Bytes.concat(Arrays.copyOfRange(data1, 0, 48), Arrays.copyOfRange(data2, 0, 48));
                BigInteger nonce1 = BigInteger.ZERO;
                BigInteger nonce2 = BigInteger.ZERO;
                if (data1.length > 48) {
                    nonce1 = new BigInteger(1, Arrays.copyOfRange(data1, 48, data1.length));
                }
                if (data2.length > 48) {
                    nonce2 = new BigInteger(1, Arrays.copyOfRange(data2, 48, data2.length));
                }

                final BigInteger nonce = nonce1.shiftLeft(16 * 8).or(nonce2);
                byte[] noncebytes = Util.prependZeros(32, nonce.toByteArray());
                noncebytes = Arrays.copyOfRange(noncebytes, noncebytes.length - 32, noncebytes.length);

                for (final MasterVerifyKey k : verifyKeys.get(pkhash)) {
                    byte[] sharedkey, xornonce;
                    logger.debug("checking key {}", Encoder.HEX.encode(k.toBytes()));
                    logger.debug("noncebytes {}", Encoder.HEX.encode(noncebytes));
                    logger.debug("noncebytes len {}", noncebytes.length);
                    sharedkey = HASH.sha256(HASH.sha256(Bytes.concat(k.toBytes(), noncebytes)));
                    xornonce = Arrays.copyOfRange(HASH.sha256(Bytes.concat(sharedkey, noncebytes)), 0, 24);
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
                    k.setFirstValidSubKey(new MasterVerifyKey(vk), t1, t2);
                    transA1HashMap.get(pkhash).remove(t1);
                    if (transA1HashMap.get(pkhash).isEmpty()) {
                        transA1HashMap.remove(pkhash);
                    }
                    return true;
                }
            }
        }
        if (!transA2HashMap.containsKey(pkhash)) {
            transA2HashMap.put(pkhash, new ArrayList<Transaction>());
        }
        transA2HashMap.get(pkhash).add(t2);
        logger.debug("nothing in A1 HashMap");
        return false;
    }

    private boolean handleECA3(final Transaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    private boolean handleECA4(final Transaction t) {
        // TODO Auto-generated method stub
        return false;
    }

    protected boolean handleTransaction(final Transaction t) {
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

    @Override
    public void pushTransaction(final Transaction t) {
        handleTransaction(t);
    }

    private void queueOnOPRETId(final MasterVerifyKey k) {
        // TODO Auto-generated method stub

    }

    /**
     * Removes the given event listener object. Returns true if the listener was
     * removed, false if that listener was never added.
     */
    public boolean removeOPRETECRevokeEventListener(final RevokeEventListener listener) {
        return revokeDB.removeRevokeEventListener(listener);
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