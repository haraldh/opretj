package org.tcpid.opretj;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;
import static org.libsodium.jni.SodiumConstants.NONCE_BYTES;
import static org.libsodium.jni.SodiumConstants.SECRETKEY_BYTES;

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
import org.libsodium.jni.crypto.Box;
import org.libsodium.jni.keys.KeyPair;
import org.libsodium.jni.keys.PublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.SigningKey;
import org.tcpid.key.VerifyKey;

import com.google.common.primitives.Bytes;

public class OPRETECParser extends OPRETBaseHandler {
    private static final Logger logger = LoggerFactory.getLogger(OPRETECParser.class);
    private static final List<Byte> OPRET_MAGIC = Bytes.asList(Utils.HEX.decode("ec0f"));
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

    private static byte[] doubleDec(final PublicKey MK, final PublicKey VK, final byte[] cipher, final byte[] nonce) {

        final KeyPair Epair = new KeyPair(Arrays.copyOfRange(
                Sha256Hash.of(Bytes.concat(nonce, VK.toBytes(), MK.toBytes())).getBytes(), 0, SECRETKEY_BYTES));

        final Box boxVK = new Box(VK, Epair.getPrivateKey());

        final byte[] nonceVK = Arrays.copyOfRange(
                Sha256Hash.of(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), VK.toBytes())).getBytes(), 0,
                NONCE_BYTES);

        final byte[] cipherMK = boxVK.decrypt(nonceVK, cipher);

        final Box boxMK = new Box(MK, Epair.getPrivateKey());

        final byte[] nonceMK = Arrays.copyOfRange(
                Sha256Hash.of(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), MK.toBytes())).getBytes(), 0,
                NONCE_BYTES);

        final byte[] clear = boxMK.decrypt(nonceMK, cipherMK);

        return clear;
    }

    private static byte[] doubleEnc(final KeyPair MKpair, final KeyPair VKpair, final byte[] clear,
            final byte[] nonce) {

        final KeyPair Epair = new KeyPair(Arrays.copyOfRange(Sha256Hash
                .of(Bytes.concat(nonce, VKpair.getPublicKey().toBytes(), MKpair.getPublicKey().toBytes())).getBytes(),
                0, SECRETKEY_BYTES));

        final Box boxMK = new Box(Epair.getPublicKey(), MKpair.getPrivateKey());

        final byte[] nonceMK = Arrays.copyOfRange(Sha256Hash
                .of(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), MKpair.getPublicKey().toBytes())).getBytes(),
                0, NONCE_BYTES);

        final byte[] cipherMK = boxMK.encrypt(nonceMK, clear);

        final Box boxVK = new Box(Epair.getPublicKey(), VKpair.getPrivateKey());

        final byte[] nonceVK = Arrays.copyOfRange(Sha256Hash
                .of(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), VKpair.getPublicKey().toBytes())).getBytes(),
                0, NONCE_BYTES);

        final byte[] cipherVK = boxVK.encrypt(nonceVK, cipherMK);

        return cipherVK;
    }

    public static Script getRevokeScript(SigningKey key) {
        final byte[] revokemsg = Bytes.concat("Revoke ".getBytes(), key.getVerifyKey().toHash());
        final byte[] sig = key.sign(revokemsg);

        final Script script = new ScriptBuilder().op(OP_RETURN).data(Utils.HEX.decode("ec0f")).data(sig)
                .data(key.getVerifyKey().getShortHash()).build();
        return script;
    }

    public static boolean checkKeyforRevoke(VerifyKey k, final byte[] sig) {
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

    public boolean cryptoSelfTest() {
        final SigningKey sk = new SigningKey();
        final VerifyKey vk = sk.getVerifyKey();

        final SigningKey msk = new SigningKey();

        final KeyPair mkpair = msk.getKeyPair();
        final KeyPair vkpair = sk.getKeyPair();
        final byte[] nonce = Arrays.copyOfRange(Sha256Hash.hash("TEST".getBytes()), 0, 8);
        final byte[] cipher = doubleEnc(mkpair, vkpair, "TEST".getBytes(), nonce);
        // System.err.println("Cipher len: " + cipher.length);
        try {
            final byte[] chk = doubleDec(msk.getVerifyKey().getPublicKey(), vk.getPublicKey(), cipher, nonce);
            return Arrays.equals(chk, "TEST".getBytes());
        } catch (final Exception e) {
            return false;
        }
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

    public void addVerifyKey(final VerifyKey key, final long earliestTime) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());
        if (!verifyKeys.containsKey(hash)) {
            verifyKeys.put(hash, new ArrayList<VerifyKey>());
        }

        verifyKeys.get(hash).add(key);
        logger.debug("Adding pkhash {}", key.getShortHash());
        addOPRET(key.getShortHash(), earliestTime);
    }

    public void removeVerifyKey(final VerifyKey key) {
        final List<Byte> hash = Bytes.asList(key.getShortHash());

        if (!verifyKeys.containsKey(hash)) {
            return;
        }

        verifyKeys.get(hash).remove(key);

        removeOPRET(key.getShortHash());
    }

    protected void queueOnOPRETRevoke(VerifyKey key) {
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
}
