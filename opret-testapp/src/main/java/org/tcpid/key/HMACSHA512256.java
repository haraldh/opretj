package org.tcpid.key;

import static org.libsodium.jni.NaCl.sodium;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.crypto.Util;

public class HMACSHA512256 {
    public static final int HMACSHA512256_BYTES = sodium().crypto_auth_hmacsha512256_bytes();
    public static final int HMACSHA512256_KEYBYTES = sodium().crypto_auth_hmacsha512256_keybytes();

    public static byte[] of(final byte[] key, final byte[] msg) {
        final byte[] hash = Util.zeros(HMACSHA512256_BYTES);
        final byte[] hashkey = Util.prependZeros(HMACSHA512256_KEYBYTES, key);
        Sodium.crypto_auth_hmacsha512256(hash, msg, msg.length, hashkey);
        return hash;
    }
}
