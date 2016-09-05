package org.tcpid.key;

import static org.libsodium.jni.NaCl.sodium;
import static org.libsodium.jni.SodiumConstants.SECRETKEY_BYTES;

import java.util.ArrayList;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.crypto.Hash;
import org.libsodium.jni.crypto.Util;
import org.libsodium.jni.encoders.Encoder;

import com.google.common.primitives.Longs;

public class MasterSigningKey extends SigningKey {
    private MasterSigningKey subkey;
    private Long subkeyindex;
    public static final Hash HASH = new Hash();
    private final ArrayList<Long> keyindex;

    public MasterSigningKey(final byte[] key, ArrayList<Long> keyindex) {
        super(key);
        subkey = null;
        subkeyindex = 0L;
        this.keyindex = new ArrayList<>(keyindex);
    }

    public MasterSigningKey(final byte[] key) {
        super(key);
        subkey = null;
        subkeyindex = 0L;
        this.keyindex = new ArrayList<>();
    }

    public MasterSigningKey getValidSubKey() {
        if (subkey == null) {
            subkey = getSubKey(subkeyindex);
        }
        return subkey;
    }

    public MasterSigningKey getSubKey(Long offset) {
        System.err.println("getSubKey");
        final byte[] la = Longs.toByteArray(offset);
        final byte[] keynum = Util.prependZeros(16 - la.length, la);
        System.err.println("getSubKey key=" + Encoder.HEX.encode(keynum));
        final byte[] appid = Util.prependZeros(14, "EC".getBytes());
        final byte[] newseed = Util.zeros(SECRETKEY_BYTES);
        sodium();
        Sodium.crypto_generichash_blake2b_salt_personal(newseed, newseed.length, null, 0, this.seed, this.seed.length,
                keynum, appid);
        final ArrayList<Long> ki = new ArrayList<>(this.keyindex);
        ki.add(offset);
        return new MasterSigningKey(newseed, ki);
    }

    public MasterSigningKey getNextValidSubKey(Long offset) {
        return getSubKey(subkeyindex + offset);
    }

    public void revokeSubKey() {
        subkey.setRevoked(true);
        subkeyindex++;
        subkey = null;
    }

    @Override
    public String toString() {
        return "Index: " + this.keyindex.toString() + " " + Encoder.HEX.encode(seed);
    }
}
