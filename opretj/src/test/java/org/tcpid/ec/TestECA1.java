/**
 *
 */
package org.tcpid.ec;

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
import org.tcpid.ec.Parser;
import org.tcpid.opretj.Transaction;

import com.google.common.primitives.Bytes;

public class TestECA1 {
    private final static Logger logger = LoggerFactory.getLogger(TestECA1.class);

    /**
     * Test method for
     * {@link org.tcpid.ec.Parser#pushTransaction(org.tcpid.opretj.Transaction)}.
     */
    @Test
    public void testPushTransaction() {
        logger.debug("testPushTransaction");

        final byte[] cipher = Encoder.HEX.decode(
                "bed9e277c3fde807eecb2100e2a4c9ec1067891b9f021e3bfbc599a3676048598e7c9801d94d9765cb965e64cfb9f493d7ae332bc85affb8bb0337b6835c51d156005db43ab8ea9b988632bfadcaee7dabf08709be248f5354d59a98e53f0cda");
        final byte[] vkb = Encoder.HEX.decode("fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c");
        final MasterVerifyKey mvk = new MasterVerifyKey(vkb);

        final byte[] vkbsha96 = Arrays.copyOfRange(Sha256Hash.of(vkb).getBytes(), 0, 12);
        final byte[] nullbyte = {};

        List<List<Byte>> opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca1")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 0, 48)));
        opret_data.add(Bytes.asList(vkbsha96));
        final Transaction t1 = new Transaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca2")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 48, 96)));
        opret_data.add(Bytes.asList(vkbsha96));
        final Transaction t2 = new Transaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca2")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 0, 48)));
        opret_data.add(Bytes.asList(vkbsha96));
        final Transaction t3 = new Transaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca1")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 48, 96)));
        opret_data.add(Bytes.asList(vkbsha96));
        final Transaction t4 = new Transaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        final Parser parser = new Parser();

        parser.addVerifyKey(mvk, 0);

        assertFalse(parser.handleTransaction(t2));
        assertFalse(parser.handleTransaction(t3));
        assertFalse(parser.handleTransaction(t4));
        assertTrue(parser.handleTransaction(t1));

        mvk.clearSubKeys();

        assertFalse(parser.handleTransaction(t1));
        assertFalse(parser.handleTransaction(t3));
        assertFalse(parser.handleTransaction(t4));
        assertTrue(parser.handleTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.handleTransaction(t1));
        assertFalse(parser.handleTransaction(t4));
        assertFalse(parser.handleTransaction(t3));
        assertTrue(parser.handleTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.handleTransaction(t2));
        assertFalse(parser.handleTransaction(t4));
        assertFalse(parser.handleTransaction(t3));
        assertTrue(parser.handleTransaction(t1));
    }

    /**
     * Test method for
     * {@link org.tcpid.ec.Parser#pushTransaction(org.tcpid.opretj.Transaction)}.
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
        final Transaction t1 = new Transaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        opret_data = new ArrayList<>();
        opret_data.add(Bytes.asList(Encoder.HEX.decode("eca2")));
        opret_data.add(Bytes.asList(Arrays.copyOfRange(cipher, 48, 96)));
        opret_data.add(Bytes.asList(vkbsha96));
        final Transaction t2 = new Transaction(Sha256Hash.of(nullbyte), Sha256Hash.of(nullbyte), opret_data);

        final Parser parser = new Parser();

        parser.addVerifyKey(mvk, 0);

        assertFalse(parser.handleTransaction(t2));
        assertTrue(parser.handleTransaction(t1));

        mvk.clearSubKeys();

        assertFalse(parser.handleTransaction(t1));
        assertTrue(parser.handleTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.handleTransaction(t1));
        assertTrue(parser.handleTransaction(t2));

        mvk.clearSubKeys();

        assertFalse(parser.handleTransaction(t2));
        assertTrue(parser.handleTransaction(t1));
    }
}
