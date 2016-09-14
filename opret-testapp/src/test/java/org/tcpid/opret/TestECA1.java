/**
 *
 */
package org.tcpid.opret;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bitcoinj.core.Sha256Hash;
import org.junit.Test;
import org.libsodium.jni.encoders.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.MasterVerifyKey;
import org.tcpid.opret.OPRETECParser;
import org.tcpid.opretj.OPRETTransaction;

import com.google.common.primitives.Bytes;

public class TestECA1 {
    private final static Logger logger = LoggerFactory.getLogger(TestECA1.class);

    /**
     * Test method for
     * {@link org.tcpid.opret.OPRETECParser#pushTransaction(org.tcpid.opretj.OPRETTransaction)}.
     */
    @Test
    public void testPushTransaction() {
        logger.debug("testPushTransaction");

        final byte[] cipher = Encoder.HEX.decode(
                "a15b671a9890a6bd0b6ed9a50193a15283001ccd72e106198b32242a906c300e263fc31dbfdaad66c40fc9796db3a464ab4313a06bbcd88fc1d503110016114c1da8bdf6e58a82be18d33c1baa96e1a9fe9c6f939b6838b30972be2de53f12d0");
        final byte[] vkb = Encoder.HEX.decode("fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c");
        final MasterVerifyKey mvk = new MasterVerifyKey(vkb);

        final byte[] vkbsha96 = Arrays.copyOfRange(Sha256Hash.of(vkb).getBytes(), 0, 12);
        final byte[] nullbyte = {};

        List<List<Byte>> opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca1")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 0, 48)));
        opret_data.add(Bytes.asList(vkbsha96));
        final OPRETTransaction t1 = new OPRETTransaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca2")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 48, 96)));
        opret_data.add(Bytes.asList(vkbsha96));
        final OPRETTransaction t2 = new OPRETTransaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca2")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 0, 48)));
        opret_data.add(Bytes.asList(vkbsha96));
        final OPRETTransaction t3 = new OPRETTransaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca1")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 48, 96)));
        opret_data.add(Bytes.asList(vkbsha96));
        final OPRETTransaction t4 = new OPRETTransaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        final OPRETECParser parser = new OPRETECParser();

        parser.addVerifyKey(mvk, 0);

        assertFalse(parser.pushTransaction(t2));
        assertFalse(parser.pushTransaction(t3));
        assertFalse(parser.pushTransaction(t4));
        assertTrue(parser.pushTransaction(t1));

        mvk.clearSubKeys();

        assertFalse(parser.pushTransaction(t1));
        assertFalse(parser.pushTransaction(t3));
        assertFalse(parser.pushTransaction(t4));
        assertTrue(parser.pushTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.pushTransaction(t1));
        assertFalse(parser.pushTransaction(t4));
        assertFalse(parser.pushTransaction(t3));
        assertTrue(parser.pushTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.pushTransaction(t2));
        assertFalse(parser.pushTransaction(t4));
        assertFalse(parser.pushTransaction(t3));
        assertTrue(parser.pushTransaction(t1));
        final MasterVerifyKey subkey = mvk.getValidSubKey();
        assertArrayEquals(subkey.toBytes(),
                Encoder.HEX.decode("e4acb361f4ec55804af6b5a1bbf5ca74ad78b4edc9a977a1dfed08872aa0a5db"));
    }

    /**
     * Test method for
     * {@link org.tcpid.opret.OPRETECParser#pushTransaction(org.tcpid.opretj.OPRETTransaction)}.
     */
    @Test
    public void testPushTransactionWithNonce() {
        logger.debug("testPushTransactionWithNonce");
        final byte[] cipher = Encoder.HEX.decode(
                "24f99184d03a6ffa5826bd9300a7fb1cff264600f335b3c6042f15cb4d3d9019fa2a9c905cdf6f6c80178def845f0340e6d2e55a7dee433a5af984760adc23e187734e5e4e76aa22f3acab172262633139b6dcd11229fe2385661a70d6c206c0");
        final byte[] vkb = Encoder.HEX.decode("fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c");
        final MasterVerifyKey mvk = new MasterVerifyKey(vkb);

        final byte[] vkbsha96 = Arrays.copyOfRange(Sha256Hash.of(vkb).getBytes(), 0, 12);
        final byte[] nullbyte = {};

        List<List<Byte>> opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca1")));
        final byte[] byte1f = { (byte) 0x11 };
        opret_data.add(Bytes.asList(Bytes.concat(Arrays.copyOfRange(cipher, 0, 48), byte1f)));
        opret_data.add(Bytes.asList(vkbsha96));
        final OPRETTransaction t1 = new OPRETTransaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca2")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 48, 96)));
        opret_data.add(Bytes.asList(vkbsha96));
        final OPRETTransaction t2 = new OPRETTransaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        final OPRETECParser parser = new OPRETECParser();

        parser.addVerifyKey(mvk, 0);

        assertFalse(parser.pushTransaction(t2));
        assertTrue(parser.pushTransaction(t1));

        mvk.clearSubKeys();

        assertFalse(parser.pushTransaction(t1));
        assertTrue(parser.pushTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.pushTransaction(t1));
        assertTrue(parser.pushTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.pushTransaction(t2));
        assertTrue(parser.pushTransaction(t1));
        final MasterVerifyKey subkey = mvk.getValidSubKey();
        assertArrayEquals(subkey.toBytes(),
                Encoder.HEX.decode("fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c"));
    }
}
