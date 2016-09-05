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
import static org.libsodium.jni.SodiumConstants.SECRETKEY_BYTES;
import static org.libsodium.jni.SodiumConstants.SIGNATURE_BYTES;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.crypto.Random;
import org.libsodium.jni.crypto.Util;
import org.libsodium.jni.encoders.Encoder;
import org.libsodium.jni.keys.KeyPair;
import org.libsodium.jni.keys.PrivateKey;

public class SigningKey implements Comparable<SigningKey> {

    protected final byte[] seed;

    private final byte[] secretKey;
    private final VerifyKey verifyKey;
    private boolean revoked;

    public SigningKey() {
        this(new Random().randomBytes(SECRETKEY_BYTES));
    }

    public SigningKey(final byte[] seed) {
        Util.checkLength(seed, SECRETKEY_BYTES);
        this.seed = seed.clone();
        this.secretKey = Util.zeros(SECRETKEY_BYTES * 2);
        final byte[] publicKey = Util.zeros(PUBLICKEY_BYTES);
        sodium();
        Util.isValid(Sodium.crypto_sign_ed25519_seed_keypair(publicKey, secretKey, seed),
                "Failed to generate a key pair");

        this.verifyKey = new VerifyKey(publicKey);
    }

    public SigningKey(final String seed, final Encoder encoder) {
        this(encoder.decode(seed));
    }

    @Override
    public int compareTo(final SigningKey other) {
        for (int i = SECRETKEY_BYTES - 1; i >= 0; i--) {
            final int thisByte = this.seed[i] & 0xff;
            final int otherByte = other.seed[i] & 0xff;
            if (thisByte > otherByte) {
                return 1;
            }
            if (thisByte < otherByte) {
                return -1;
            }
        }
        return 0;
    }

    public KeyPair getKeyPair() {
        final byte[] sk = Util.zeros(SECRETKEY_BYTES);
        sodium();
        Sodium.crypto_sign_ed25519_sk_to_curve25519(sk, this.secretKey);
        return new KeyPair(sk);

    }

    public PrivateKey getPrivateKey() {
        final byte[] sk = Util.zeros(SECRETKEY_BYTES);
        sodium();
        Sodium.crypto_sign_ed25519_sk_to_curve25519(sk, this.secretKey);
        return new PrivateKey(sk);
    }

    public VerifyKey getVerifyKey() {
        return this.verifyKey;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(final boolean revoked) {
        if (this.revoked != true) {
            this.revoked = revoked;
        }
    }

    public byte[] sign(final byte[] message) {
        byte[] signature = Util.prependZeros(SIGNATURE_BYTES, message);
        final int[] bufferLen = new int[1];
        sodium();
        Sodium.crypto_sign_ed25519(signature, bufferLen, message, message.length, secretKey);
        signature = Util.slice(signature, 0, SIGNATURE_BYTES);
        return signature;
    }

    public String sign(final String message, final Encoder encoder) {
        final byte[] signature = sign(encoder.decode(message));
        return encoder.encode(signature);
    }

    public byte[] toBytes() {
        return seed;
    }

    @Override
    public String toString() {
        return Encoder.HEX.encode(seed);
    }
}
