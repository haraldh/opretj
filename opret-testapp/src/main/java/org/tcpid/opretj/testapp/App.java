package org.tcpid.opretj.testapp;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Scanner;

import org.abstractj.kalium.keys.SigningKey;
import org.abstractj.kalium.keys.VerifyKey;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet.SendResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.opretj.OPRETECParser;
import org.tcpid.opretj.OPRETWallet;
import org.tcpid.opretj.OPRETWalletAppKit;

import com.google.common.primitives.Bytes;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(App.class);

    public static final long OPRET_BIRTHDAY = 1471989600;
    static byte[] rawKey = Sha256Hash.hash("TESTSEED".getBytes());
    static SigningKey sk = new SigningKey(rawKey);
    static VerifyKey v = sk.getVerifyKey();
    private static byte[] pkhash = Sha256Hash.hash(v.toBytes());
    static byte[] revokemsg = Bytes.concat("Revoke ".getBytes(), pkhash);

    public static void check(final byte[] pkhash, final byte[] sig) {
        logger.warn("CHECKING REVOKE PK {} - SIG {}", Utils.HEX.encode(pkhash), Utils.HEX.encode(sig));

        if (!Arrays.equals(App.pkhash, pkhash)) {
            logger.warn("Unknown PK {}", Utils.HEX.encode(pkhash));
            return;
        }

        logger.warn("Using VerifyKey {}", v);

        if (v.verify(revokemsg, sig)) {
            logger.warn("REVOKED VerifyKey {}", v);
        } else {
            logger.warn("SIGNATURE does not match!");
        }
    }

    private static String executeCommand(final String command) {

        final StringBuffer output = new StringBuffer();

        Process p;
        try {
            p = Runtime.getRuntime().exec(command);
            p.waitFor();
            final BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line = "";
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

        } catch (final Exception e) {
            e.printStackTrace();
        }

        return output.toString();

    }

    public static void main(final String[] args) throws Exception {
        final OptionParser parser = new OptionParser();
        final OptionSpec<NetworkEnum> net = parser.accepts("net", "The network to run the examples on")
                .withRequiredArg().ofType(NetworkEnum.class).defaultsTo(NetworkEnum.TEST);
        parser.accepts("help", "Displays program options");
        final OptionSet opts = parser.parse(args);
        if (opts.has("help") || !opts.has(net)) {
            System.err.println("usage: App --net=MAIN/TEST/REGTEST");
            parser.printHelpOn(System.err);
            return;
        }
        final NetworkParameters params = net.value(opts).get();

        final OPRETECParser bs = new OPRETECParser();

        bs.addOPRETECRevokeEventListener((pkhash, sig) -> check(pkhash, sig));

        long earliestTime;
        if (params.getId().equals(NetworkParameters.ID_REGTEST)) {
            earliestTime = OPRET_BIRTHDAY;
        } else if (params.getId().equals(NetworkParameters.ID_TESTNET)) {
            earliestTime = OPRET_BIRTHDAY;
        } else {
            earliestTime = Utils.currentTimeSeconds();
        }

        bs.addOPRET(pkhash, earliestTime);
        // bs.addOPRET(Sha256Hash.hash("test1".getBytes()), earliestTime);
        // bs.addOPRET(Utils.HEX.decode("0f490dee643b01b06e0ea84c253a90050a3543cfb7c74319fb47b04afee5b872"),
        // earliestTime);

        // Now we initialize a new WalletAppKit. The kit handles all the
        // boilerplate for us and is the easiest way to get everything up and
        // running.
        // Have a look at the WalletAppKit documentation and its source to
        // understand what's happening behind the scenes:
        // https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/kits/WalletAppKit.java
        final OPRETWalletAppKit kit = new OPRETWalletAppKit(params, new File("."), "opretwallet" + params.getId(), bs);

        // In case you want to connect with your local bitcoind tell the kit to
        // connect to localhost.
        // You must do that in reg test mode.
        if (params.getId().equals(NetworkParameters.ID_REGTEST)) {
            kit.connectToLocalHost();
        }
        kit.setCheckpoints(App.class.getResourceAsStream("/" + params.getId() + ".checkpoints"));
        // Now we start the kit and sync the blockchain.
        // bitcoinj is working a lot with the Google Guava libraries. The
        // WalletAppKit extends the AbstractIdleService. Have a look at the
        // introduction to Guava services:
        // https://github.com/google/guava/wiki/ServiceExplained
        kit.startAsync();
        kit.awaitRunning();

        final OPRETWallet wallet = kit.opretwallet();

        wallet.addCoinsReceivedEventListener((wallet1, tx, prevBalance, newBalance) -> {
            System.out.println("-----> coins resceived: " + tx.getHashAsString());
            System.out.println("received: " + tx.getValue(wallet1));
        });

        wallet.addCoinsSentEventListener((wallet1, tx, prevBalance, newBalance) -> System.out.println("coins sent"));

        wallet.addKeyChainEventListener(keys -> System.out.println("new key added"));

        wallet.addScriptsChangeEventListener(
                (wallet1, scripts, isAddingScripts) -> System.out.println("new script added"));

        wallet.addTransactionConfidenceEventListener((wallet1, tx) -> {
            System.out.println("-----> confidence changed: " + tx.getHashAsString());
            final TransactionConfidence confidence = tx.getConfidence();
            System.out.println("new block depth: " + confidence.getDepthInBlocks());
        });

        // wallet.allowSpendingUnconfirmedTransactions();

        // Ready to run. The kit syncs the blockchain and our wallet event
        // listener gets notified when something happens.
        // To test everything we create and print a fresh receiving address.
        // Send some coins to that address and see if everything works.
        final String receiveStr = wallet.freshReceiveAddress().toString();
        final Scanner input = new Scanner(System.in);

        display: while (true) {

            System.out.println("-- Actions --");
            System.out.println("Select an option: \n" + "  0) QUIT\n" + "  1) Display Balance\n"
                    + "  2) Display Receive Address\n" + "  3) Send OP_Return\n");
            try {
                final int selection = input.nextInt();

                switch (selection) {
                case 0:
                    System.out.println("Returning...");
                    break display;
                case 1:
                    System.out.println("Balance: " + wallet.getBalance().toFriendlyString());
                    break;
                case 2:
                    System.out.println("send money to: " + receiveStr);
                    try {
                        System.out.print(executeCommand("qrencodes -t UTF8 -o - " + receiveStr));
                    } catch (final Exception e) {
                        ;
                    }
                    break;
                case 3:
                    sendOPReturn(kit);
                    break;
                default:
                    System.out.println("Invalid action.");
                    break;
                }
            } catch (final InputMismatchException e) {
                ;
            }
            input.nextLine();

        }
        input.close();

        // Make sure to properly shut down all the running services when you
        // manually want to stop the kit. The WalletAppKit registers a runtime
        // ShutdownHook so we actually do not need to worry about that when our
        // application is stopping.
        System.out.println("shutting down again");
        kit.stopAsync();
        kit.awaitTerminated();
    }

    private static boolean sendOPReturn(final OPRETWalletAppKit kit) {
        final OPRETWallet wallet = kit.opretwallet();
        final NetworkParameters params = wallet.getNetworkParameters();

        Transaction t = new Transaction(params);
        final byte[] sig = sk.sign(revokemsg);

        Script script = new ScriptBuilder().op(OP_RETURN).data(Utils.HEX.decode("ec1d")).data(Utils.HEX.decode("fe"))
                .data(pkhash).data(Arrays.copyOfRange(sig, 0, 32)).build();
        t.addOutput(Coin.ZERO, script);
        t.addOutput(Transaction.DEFAULT_TX_FEE, wallet.freshAddress(KeyPurpose.CHANGE));
        SendRequest request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        SendResult sr = null;

        try {
            sr = wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }
        logger.debug("SendRequest {}", request);

        script = new ScriptBuilder().op(OP_RETURN).data(Utils.HEX.decode("ec1d")).data(Utils.HEX.decode("ff"))
                .data(pkhash).data(Arrays.copyOfRange(sig, 32, 64)).build();
        t = new Transaction(params);

        for (final TransactionOutput out : sr.tx.getOutputs()) {
            if (out.getValue().compareTo(Transaction.DEFAULT_TX_FEE) == 0) {
                logger.debug("Add Output: {} of value {}", out, out.getValue());
                t.addInput(out);
            }
        }

        t.addOutput(Coin.ZERO, script);
        request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        sr = null;

        try {
            sr = wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }

        logger.debug("SendRequest {}", request);
        return true;
    }
}
