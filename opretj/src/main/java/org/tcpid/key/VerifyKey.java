/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.tcpid.key;

import static org.libsodium.jni.NaCl.sodium;
import static org.libsodium.jni.SodiumConstants.PUBLICKEY_BYTES;
import static org.libsodium.jni.SodiumConstants.SIGNATURE_BYTES;

import java.util.Arrays;

import org.libsodium.jni.crypto.Hash;
import org.libsodium.jni.crypto.Util;
import org.libsodium.jni.encoders.Encoder;
import org.libsodium.jni.keys.PublicKey;

public class VerifyKey implements Comparable<VerifyKey> {
    public static final Hash HASH = new Hash();

    private final byte[] key;
    private final byte[] hash;
    private final byte[] shortHash;
    private boolean revoked;

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        if (this.revoked != true) {
            this.revoked = revoked;
        }
    }

    public VerifyKey(byte[] key) {
        Util.checkLength(key, PUBLICKEY_BYTES);
        this.key = key;
        this.hash = HASH.sha256(key);
        this.shortHash = Arrays.copyOfRange(hash, 0, 12);
        this.revoked = false;
    }

    public VerifyKey(String key, Encoder encoder) {
        this(encoder.decode(key));
    }

    public PublicKey getPublicKey() {
        final byte[] pk = Util.zeros(PUBLICKEY_BYTES);
        sodium().crypto_sign_ed25519_pk_to_curve25519(pk, this.key);
        return new PublicKey(pk);
    }

    public byte[] toBytes() {
        return key;
    }

    @Override
    public String toString() {
        return Encoder.HEX.encode(key);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if ((o == null) || (getClass() != o.getClass())) {
            return false;
        }
        return Arrays.equals(key, ((VerifyKey) o).key);
    }

    public boolean verify(byte[] message, byte[] signature) {
        Util.checkLength(signature, SIGNATURE_BYTES);
        final byte[] sigAndMsg = Util.merge(signature, message);
        final byte[] buffer = Util.zeros(sigAndMsg.length);
        final int[] bufferLen = new int[1];

        return Util.isValid(sodium().crypto_sign_ed25519_open(buffer, bufferLen, sigAndMsg, sigAndMsg.length, key),
                "signature was forged or corrupted");
    }

    public boolean verify(String message, String signature, Encoder encoder) {
        return verify(encoder.decode(message), encoder.decode(signature));
    }

    public byte[] toHash() {
        return this.hash;
    }

    public byte[] getShortHash() {
        return this.shortHash;
    }

    @Override
    public int compareTo(final VerifyKey other) {
        for (int i = PUBLICKEY_BYTES - 1; i >= 0; i--) {
            final int thisByte = this.key[i] & 0xff;
            final int otherByte = other.key[i] & 0xff;
            if (thisByte > otherByte) {
                return 1;
            }
            if (thisByte < otherByte) {
                return -1;
            }
        }
        return 0;
    }

}
