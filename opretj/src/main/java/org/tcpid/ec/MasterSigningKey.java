package org.tcpid.ec;

import java.util.ArrayList;

import org.libsodium.jni.crypto.Hash;
import org.libsodium.jni.encoders.Encoder;

import com.google.common.primitives.Longs;

public class MasterSigningKey extends SigningKey {
    public static final Hash HASH = new Hash();
    private MasterSigningKey subkey;
    private Long subkeyindex;
    private final ArrayList<Long> keyindex;

    public MasterSigningKey(final byte[] key) {
        super(key);
        subkey = null;
        subkeyindex = 0L;
        this.keyindex = new ArrayList<>();
    }

    public MasterSigningKey(final byte[] key, final ArrayList<Long> keyindex) {
        super(key);
        subkey = null;
        subkeyindex = 0L;
        this.keyindex = new ArrayList<>(keyindex);
    }

    public MasterVerifyKey getMasterVerifyKey() {
        return new MasterVerifyKey(this.getVerifyKey().toBytes());
    }

    public MasterSigningKey getNextValidSubKey(final Long offset) {
        return getSubKey(subkeyindex + offset);
    }

    public MasterSigningKey getSubKey(final Long offset) {
        final byte[] ob = Longs.toByteArray(offset);
        final byte[] newseed = HMACSHA512256.of(seed, ob);
        final ArrayList<Long> ki = new ArrayList<>(this.keyindex);
        ki.add(offset);
        return new MasterSigningKey(newseed, ki);
    }

    public MasterSigningKey getValidSubKey() {
        if (subkey == null) {
            subkey = getSubKey(subkeyindex);
        }
        return subkey;
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
