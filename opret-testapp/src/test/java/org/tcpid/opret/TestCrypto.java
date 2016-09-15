package org.tcpid.opret;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.libsodium.jni.NaCl.sodium;
import static org.libsodium.jni.SodiumConstants.NONCE_BYTES;
import static org.libsodium.jni.SodiumConstants.SECRETKEY_BYTES;

import java.math.BigInteger;
import java.util.Arrays;

import org.bitcoinj.core.Utils;
import org.junit.Test;
import org.libsodium.jni.Sodium;
import org.libsodium.jni.crypto.Hash;
import org.libsodium.jni.crypto.Util;
import org.libsodium.jni.encoders.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.HMACSHA512256;
import org.tcpid.key.MasterSigningKey;
import org.tcpid.key.MasterVerifyKey;

import com.google.common.primitives.Bytes;

public class TestCrypto {
    private final static Logger logger = LoggerFactory.getLogger(TestCrypto.class);
    private final static Hash HASH = new Hash();

    @Test
    public void testDerive() {
        logger.debug("testDerive");
        assertTrue("NONCE_BYTES > HMACSHA512256.HMACSHA512256_BYTES", NONCE_BYTES <= HMACSHA512256.HMACSHA512256_BYTES);
        assertEquals(SECRETKEY_BYTES, HMACSHA512256.HMACSHA512256_BYTES);

        final MasterSigningKey msk = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));

        assertArrayEquals(Utils.HEX.decode("4071b2b3db7cc7aecd0b23608e96f44f08463ea0ee0a0c12f5fa21ff449deb55"),
                msk.toBytes());

        final MasterSigningKey subkey = msk.getSubKey(1L).getSubKey(2L).getSubKey(3L).getSubKey(4L);
        assertArrayEquals(Utils.HEX.decode("00cb0c8748318d27eab65159a2261c028d764c1154fc302b9b046aa2bbefab27"),
                subkey.toBytes());

        final BigInteger biMSK = new BigInteger(1, msk.toBytes());
        BigInteger biSub = new BigInteger(1, subkey.toBytes());
        final BigInteger pow2_256 = new BigInteger("10000000000000000000000000000000000000000000000000000000000000000",
                16);
        final BigInteger biDiff = biSub.subtract(biMSK).mod(pow2_256);

        biSub = biMSK.add(biDiff).mod(pow2_256);
        final byte[] bisubb = biSub.toByteArray();

        assertArrayEquals(bisubb, subkey.toBytes());
    }

    @Test
    public void testSign() {
        logger.debug("testSign");
        final MasterSigningKey msk = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));
        final MasterVerifyKey vk = msk.getMasterVerifyKey();
        final byte[] revokemsg = Bytes.concat("Revoke ".getBytes(), vk.toHash());
        final byte[] sig = msk.sign(revokemsg);
        assertTrue("Verification of signature failed.", vk.verify(revokemsg, sig));
    }

    @Test
    public void testSignEnc() {
        logger.debug("testSignEnc");
        final MasterSigningKey msk = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));
        final MasterVerifyKey subkey = msk.getSubKey(1L).getMasterVerifyKey();
        final MasterVerifyKey vk = msk.getMasterVerifyKey();
        byte[] sig = msk.sign(subkey.toBytes());

        logger.debug("using key {}", Encoder.HEX.encode(vk.toBytes()));
        final byte[] noncebytes = Util.zeros(32);
        final byte[] sharedkey = HASH.sha256(HASH.sha256(Bytes.concat(vk.toBytes(), noncebytes)));
        final byte[] xornonce = Arrays.copyOfRange(HASH.sha256(Bytes.concat(sharedkey, noncebytes)), 0, 24);
        logger.debug("xornonce {}", Encoder.HEX.encode(xornonce));
        logger.debug("sharedkey {}", Encoder.HEX.encode(sharedkey));

        final byte[] cipher = Util.zeros(96);
        byte[] msg = Bytes.concat(subkey.toBytes(), sig);
        assertEquals(96, msg.length);

        sodium();
        Sodium.crypto_stream_xsalsa20_xor(cipher, msg, 96, xornonce, sharedkey);
        assertEquals(96, cipher.length);
        logger.debug("Clear : {}", Encoder.HEX.encode(msg));
        logger.debug("Cipher: {}", Encoder.HEX.encode(cipher));
        msg = Util.zeros(96);
        Sodium.crypto_stream_xsalsa20_xor(msg, cipher, 96, xornonce, sharedkey);

        final byte[] vkb = Arrays.copyOfRange(msg, 0, 32);
        sig = Arrays.copyOfRange(msg, 32, 96);
        logger.debug("vkb : {}", Encoder.HEX.encode(vkb));
        assertTrue("Verification of signature failed.", vk.verify(vkb, sig));
        assertArrayEquals(subkey.toBytes(), vkb);
    }

    @Test
    public void testSignEncNext() {
        logger.debug("testSignEncNext");

        final MasterSigningKey msk = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));
        final MasterVerifyKey mvk = msk.getMasterVerifyKey();
        final MasterVerifyKey prev = msk.getSubKey(1L).getMasterVerifyKey();
        final MasterVerifyKey next = msk.getSubKey(2L).getMasterVerifyKey();

        byte[] sig = msk.sign(next.toBytes());

        logger.debug("using key {}", Encoder.HEX.encode(prev.toBytes()));
        final byte[] sharedkey = HASH.sha256(HASH.sha256(prev.toBytes()));
        final byte[] xornonce = Arrays.copyOfRange(HASH.sha256(sharedkey), 0, 24);
        logger.debug("xornonce {}", Encoder.HEX.encode(xornonce));
        logger.debug("sharedkey {}", Encoder.HEX.encode(sharedkey));

        final byte[] cipher = Util.zeros(96);
        byte[] msg = Bytes.concat(next.toBytes(), sig);
        assertEquals(96, msg.length);

        sodium();
        Sodium.crypto_stream_xsalsa20_xor(cipher, msg, 96, xornonce, sharedkey);
        assertEquals(96, cipher.length);
        logger.debug("Clear : {}", Encoder.HEX.encode(msg));
        logger.debug("Cipher: {}", Encoder.HEX.encode(cipher));
        msg = Util.zeros(96);
        Sodium.crypto_stream_xsalsa20_xor(msg, cipher, 96, xornonce, sharedkey);

        final byte[] vkb = Arrays.copyOfRange(msg, 0, 32);
        sig = Arrays.copyOfRange(msg, 32, 96);
        logger.debug("vkb : {}", Encoder.HEX.encode(vkb));
        assertTrue("Verification of signature failed.", mvk.verify(vkb, sig));
        assertArrayEquals(next.toBytes(), vkb);
    }

    @Test
    public void testSignEncNoncebytes() {
        logger.debug("testSignEncNoncebytes");

        final MasterSigningKey msk = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));
        final MasterVerifyKey vk = msk.getMasterVerifyKey();
        byte[] sig = msk.sign(vk.toBytes());

        logger.debug("nonce: using key {}", Encoder.HEX.encode(vk.toBytes()));
        final byte[] noncebytes = Encoder.HEX
                .decode("0000000000000000000000000000001100000000000000000000000000000000");
        final byte[] sharedkey = HASH.sha256(HASH.sha256(Bytes.concat(vk.toBytes(), noncebytes)));
        final byte[] xornonce = Arrays.copyOfRange(HASH.sha256(Bytes.concat(sharedkey, noncebytes)), 0, 24);
        logger.debug("nonce: nonce {}", Encoder.HEX.encode(xornonce));
        logger.debug("nonce: sharedkey {}", Encoder.HEX.encode(sharedkey));

        final byte[] cipher = Util.zeros(96);
        byte[] msg = Bytes.concat(vk.toBytes(), sig);
        assertEquals(96, msg.length);

        sodium();
        Sodium.crypto_stream_xsalsa20_xor(cipher, msg, 96, xornonce, sharedkey);
        assertEquals(96, cipher.length);
        logger.debug("nonce: Clear : {}", Encoder.HEX.encode(msg));
        logger.debug("nonce: Cipher: {}", Encoder.HEX.encode(cipher));
        msg = Util.zeros(96);
        Sodium.crypto_stream_xsalsa20_xor(msg, cipher, 96, xornonce, sharedkey);

        final byte[] vkb = Arrays.copyOfRange(msg, 0, 32);
        sig = Arrays.copyOfRange(msg, 32, 96);
        logger.debug("nonce: vkb : {}", Encoder.HEX.encode(vkb));
        assertTrue("nonce: Verification of signature failed.", vk.verify(vkb, sig));
        assertArrayEquals(vk.toBytes(), vkb);
    }
}
