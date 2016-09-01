package org.tcpid.opretj.testapp;

import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;

import org.abstractj.kalium.crypto.Box;
import org.abstractj.kalium.crypto.Hash;
import org.abstractj.kalium.keys.KeyPair;
import org.abstractj.kalium.keys.PublicKey;
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
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.KeyChain.KeyPurpose;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet.SendResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.opretj.OPRETECParser;
import org.tcpid.opretj.OPRETWallet;
import org.tcpid.opretj.OPRETWalletAppKit;

import com.google.common.primitives.Bytes;
import com.google.common.util.concurrent.Service;

import jline.console.ConsoleReader;
import jline.console.completer.StringsCompleter;
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

    public static void checkKey(final byte[] pkhash, final byte[] sig) {
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

    private static boolean cryptoSelfTest() {
        final KeyPair MKpair = new KeyPair();
        final KeyPair VKpair = new KeyPair();
        final byte[] nonce = Arrays.copyOfRange(Sha256Hash.hash("TEST".getBytes()), 0, 8);
        final byte[] cipher = doubleEnc(MKpair, VKpair, "TEST".getBytes(), nonce);
        // System.err.println("Cipher len: " + cipher.length);
        final byte[] chk = doubleDec(MKpair.getPublicKey(), VKpair.getPublicKey(), cipher, nonce);
        return Arrays.equals(chk, "TEST".getBytes());
    }

    private static void displayBalance(final OPRETWalletAppKit kit, final PrintWriter out) {
        out.write("Balance: " + kit.wallet().getBalance().toFriendlyString() + "\n");
        out.flush();
    }

    private static void displayHelp(PrintWriter out) {
        out.write("Available Commands:\n");
        out.write("\n");
        out.write("help            - this screen\n");
        out.write("quit            - exit the application\n");
        out.write("balance         - show your available balance\n");
        out.write("receive         - display an address to receive coins\n");
        out.write("empty <address> - send all coins to the address\n");
        out.write("opret           - send opret\n");
        out.write("\n");

        out.flush();
    }

    private static byte[] doubleDec(final PublicKey MK, final PublicKey VK, final byte[] cipher, final byte[] nonce) {
        final Hash h = new Hash();

        final KeyPair Epair = new KeyPair(
                Arrays.copyOfRange(h.blake2(Bytes.concat(nonce, VK.toBytes(), MK.toBytes())), 0, 32));

        final Box boxVK = new Box(VK.toBytes(), Epair.getPrivateKey().toBytes());
        final byte[] nonceVK = Arrays
                .copyOfRange(h.blake2(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), VK.toBytes())), 0, 24);

        final byte[] cipherMK = boxVK.decrypt(nonceVK, cipher);

        final Box boxMK = new Box(MK.toBytes(), Epair.getPrivateKey().toBytes());

        final byte[] nonceMK = Arrays
                .copyOfRange(h.blake2(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), MK.toBytes())), 0, 24);

        final byte[] clear = boxMK.decrypt(nonceMK, cipherMK);

        return clear;
    }

    private static byte[] doubleEnc(final KeyPair MKpair, final KeyPair VKpair, final byte[] clear,
            final byte[] nonce) {
        final Hash h = new Hash();

        final KeyPair Epair = new KeyPair(Arrays.copyOfRange(
                h.blake2(Bytes.concat(nonce, VKpair.getPublicKey().toBytes(), MKpair.getPublicKey().toBytes())), 0,
                32));

        final Box boxMK = new Box(Epair.getPublicKey().toBytes(), MKpair.getPrivateKey().toBytes());
        final byte[] nonceMK = Arrays.copyOfRange(
                h.blake2(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), MKpair.getPublicKey().toBytes())), 0, 24);

        final byte[] cipherMK = boxMK.encrypt(nonceMK, clear);

        final Box boxVK = new Box(Epair.getPublicKey().toBytes(), VKpair.getPrivateKey().toBytes());
        final byte[] nonceVK = Arrays.copyOfRange(
                h.blake2(Bytes.concat(nonce, Epair.getPrivateKey().toBytes(), VKpair.getPublicKey().toBytes())), 0, 24);
        final byte[] cipherVK = boxVK.encrypt(nonceVK, cipherMK);
        return cipherVK;
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

    private static void handleConsole(final OPRETWalletAppKit kit) throws IOException {
        final String receiveStr = kit.wallet().freshReceiveAddress().toString();
        final ConsoleReader reader = new ConsoleReader();
        final String[] cmds = { "help", "quit", "exit", "balance", "receive", "empty", "opret" };
        reader.addCompleter(new StringsCompleter(cmds));
        final PrintWriter out = new PrintWriter(reader.getOutput());
        reader.setPrompt("opret> ");
        String line;
        displayHelp(out);
        displayBalance(kit, out);

        while ((line = reader.readLine()) != null) {
            final String[] argv = line.split("\\s");
            if (argv.length == 0) {
                continue;
            }

            final String cmd = argv[0];
            final String args[] = Arrays.copyOfRange(argv, 1, argv.length);

            switch (cmd.toLowerCase()) {
            case "quit":
                return;
            case "help":
                displayHelp(out);
                break;
            case "balance":
                displayBalance(kit, out);
                break;
            case "receive":
                out.write("send money to: " + receiveStr + "\n");
                try {
                    out.write(executeCommand("qrencode -t UTF8 -o - " + receiveStr));
                } catch (final Exception e) {
                    ;
                }
                out.flush();
                break;
            case "empty":
                if (args.length != 1) {
                    out.println("empty needs a receive address!");
                    continue;
                }
                break;
            case "opret":
                sendOPReturn(kit, out);
                break;
            }
        }
    }

    public static void main(final String[] args) throws Exception {

        final boolean chk = cryptoSelfTest();
        if (chk) {
            System.err.println("Crypto self test: PASSED");
        } else {
            System.err.println("Crypto self test: FAILED");
            System.exit(-1);
        }

        final OptionParser parser = new OptionParser();
        final OptionSpec<NetworkEnum> net = parser.accepts("net", "The network to run the examples on")
                .withRequiredArg().ofType(NetworkEnum.class).defaultsTo(NetworkEnum.TEST);
        parser.accepts("help", "Displays program options");
        final OptionSet opts = parser.parse(args);
        if (opts.has("help")) {
            System.err.println("usage: App --net=MAIN/TEST/REGTEST");
            parser.printHelpOn(System.err);
            return;
        }
        if (!opts.has(net)) {
            System.err.println("No net specified, using TestNet!");
        }

        final NetworkParameters params = net.value(opts).get();

        final OPRETECParser bs = new OPRETECParser();

        bs.addOPRETECRevokeEventListener((pkhash, sig) -> checkKey(pkhash, sig));

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

        final OPRETWalletAppKit kit = new OPRETWalletAppKit(params, new File("."), "opretwallet" + params.getId(), bs);

        kit.addListener(new Service.Listener() {
            @Override
            public void failed(final Service.State from, final Throwable failure) {
                logger.error(failure.getMessage());
                System.exit(-1);
            }
        }, Threading.SAME_THREAD);

        if (params.getId().equals(NetworkParameters.ID_REGTEST)) {
            kit.connectToLocalHost();
        }
        kit.setCheckpoints(App.class.getResourceAsStream("/" + params.getId() + ".checkpoints"));
        kit.startAsync();

        System.out.println("Please wait for the blockchain to be downloaded!");

        try {
            kit.awaitRunning();
        } catch (final Exception e) {
            System.err.println("Aborting - shutting down");
            // e.printStackTrace();
            kit.stopAsync();
            kit.awaitTerminated();
            System.exit(-1);
        }

        final OPRETWallet wallet = kit.opretwallet();

        wallet.addCoinsReceivedEventListener((wallet1, tx, prevBalance, newBalance) -> {
            System.out.println("-----> coins resceived: " + tx.getHashAsString());
            System.out.println("received: " + tx.getValue(wallet1));
        });

        wallet.addCoinsSentEventListener(Threading.SAME_THREAD,
                (wallet1, tx, prevBalance, newBalance) -> System.out.println("coins sent"));

        wallet.addKeyChainEventListener(Threading.SAME_THREAD, keys -> System.out.println("new key added"));

        wallet.addScriptChangeEventListener(Threading.SAME_THREAD,
                (wallet1, scripts, isAddingScripts) -> System.out.println("new script added"));

        wallet.addTransactionConfidenceEventListener(Threading.SAME_THREAD, (wallet1, tx) -> {
            System.out.println("-----> confidence changed: " + tx.getHashAsString());
            final TransactionConfidence confidence = tx.getConfidence();
            System.out.println("new block depth: " + confidence.getDepthInBlocks());
        });
        // wallet.allowSpendingUnconfirmedTransactions();

        handleConsole(kit);

        System.out.println("shutting down");
        kit.stopAsync();
        kit.awaitTerminated();
    }

    private static boolean sendOPReturn(final OPRETWalletAppKit kit, PrintWriter output) {
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
            output.println(e.getLocalizedMessage());
            output.flush();
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
            output.println(e.getLocalizedMessage());
            output.flush();
            return false;
        }

        logger.debug("SendRequest {}", request);
        return true;
    }
}
