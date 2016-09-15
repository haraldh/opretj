package org.tcpid.opretj.testapp;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.LinkedList;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.SendRequest;
import org.libsodium.jni.crypto.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.MasterSigningKey;
import org.tcpid.key.MasterVerifyKey;
import org.tcpid.opret.OPRETECParser;
import org.tcpid.opretj.OPRETWallet;
import org.tcpid.opretj.OPRETWalletAppKit;

import com.google.common.util.concurrent.Service;

import jline.console.ConsoleReader;
import jline.console.completer.StringsCompleter;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

public class App {
    public static final Hash HASH = new Hash();
    public final static long OPRET_BIRTHDAY = 1471989600;

    private final static Logger logger = LoggerFactory.getLogger(App.class);
    private final static MasterSigningKey SK = new MasterSigningKey(HASH.sha256("TESTSEED".getBytes()));
    public final static LinkedList<MasterVerifyKey> WATCHKEYS = new LinkedList<>();
    public static OPRETWalletAppKit KIT;
    public static NetworkParameters PARAMS;
    public final static OPRETECParser PARSER = new OPRETECParser();
    public static String WALLETNAME;

    private static void displayBalance(final OPRETWalletAppKit kit, final PrintWriter out) {
        if (kit == null) {
            out.println("Need blockchain scan");
            out.flush();
            return;
        }
        out.write("Balance: " + kit.wallet().getBalance().toFriendlyString() + "\n");
        out.flush();
    }

    private static void displayHelp(final PrintWriter out) {
        out.write("Available Commands:\n");
        out.write("\n");
        out.write("help            - this screen\n");
        out.write("quit            - exit the application\n");
        out.write("scan            - scan the blockchain\n");
        out.write("balance         - show your available balance\n");
        out.write("receive         - display an address to receive coins\n");
        out.write("empty <address> - send all coins to the address\n");
        out.write("\n");
        out.write("newkey <hashseed>         - create a new key with seed = sha256(hashseed)\n");
        out.write("listsub <index> <key>     - list the subkey of <key> with optional <index>\n");
        out.write("revoke <key>              - revoke a key on the blockchain\n");
        out.write("announce <index> <master> - announce the subkey <index> signed with its <master> key\n");
        out.write("watch <key>               - listen on the blockchain for all actions on <key>\n");
        out.write("listwatch <key>           - listen on the blockchain for all actions on <key>\n");
        out.write("\n");

        out.flush();
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

    private static void handleConsole() throws IOException {
        final ConsoleReader reader = new ConsoleReader();
        final String[] cmds = { "help", "quit", "exit", "balance", "receive", "empty", "opret", "newkey", "listsub",
                "revoke", "announce", "listen", "listwatch", "scan", "watch" };
        reader.addCompleter(new StringsCompleter(cmds));
        final PrintWriter out = new PrintWriter(reader.getOutput());
        reader.setPrompt("opret> ");
        String line;
        displayHelp(out);
        displayBalance(KIT, out);

        while ((line = reader.readLine()) != null) {
            String[] argv = line.split("\\s");
            if (argv.length == 0) {
                continue;
            }

            final String cmd = argv[0];
            if (cmd.isEmpty()) {
                continue;
            }

            argv = Arrays.copyOfRange(argv, 1, argv.length);

            switch (cmd.toLowerCase()) {
            case "quit":
            case "exit":
                return;
            case "help":
                displayHelp(out);
                break;
            case "balance":
                displayBalance(KIT, out);
                break;
            case "receive":
                final String receiveStr = KIT.wallet().freshReceiveAddress().toString();

                out.write("send money to: " + receiveStr + "\n");
                try {
                    out.write(executeCommand("qrencode -t UTF8 -o - " + receiveStr));
                } catch (final Exception e) {
                    ;
                }
                out.flush();
                break;
            case "empty":
                if (argv.length != 1) {
                    out.println("'empty <address>' needs a valid receive address!");
                    continue;
                }
                out.println("'" + argv[0] + "'");
                out.flush();
                try {
                    final SendRequest request = SendRequest.emptyWallet(Address.fromBase58(KIT.params(), argv[0]));
                    try {
                        KIT.wallet().sendCoins(request);
                    } catch (final InsufficientMoneyException e) {
                        out.println(e.getLocalizedMessage());
                        out.flush();
                    }
                } catch (final AddressFormatException e) {
                    out.println(e.getLocalizedMessage());
                    out.flush();
                }
                break;
            case "newkey": {
                if (argv.length != 1) {
                    out.println("'newkey <hash>' needs a an argument");
                    continue;
                }
                final byte[] seed = Sha256Hash.of(argv[0].getBytes()).getBytes();
                final MasterSigningKey key = new MasterSigningKey(seed);
                out.println("Private: " + key.toString());
                out.println("Public: " + key.getMasterVerifyKey().toString());
                out.println("Sha256(pub): " + Utils.HEX.encode(key.getMasterVerifyKey().toHash()));
                out.println("Sha256(pub)[0:12]: " + Utils.HEX.encode(key.getMasterVerifyKey().getShortHash()));
                out.flush();
            }
                break;
            case "listsub": {
                if (argv.length != 2) {
                    out.println("'listsub <index> <key>' needs two arguments");
                    continue;
                }
                final Long index = new Long(argv[0]);
                final MasterSigningKey mk = new MasterSigningKey(Utils.HEX.decode(argv[1]));
                final MasterSigningKey key = mk.getSubKey(index);
                out.println("Private: " + key.toString());
                out.println("Public: " + key.getMasterVerifyKey().toString());
                out.println("Sha256(pub): " + Utils.HEX.encode(key.getMasterVerifyKey().toHash()));
                out.println("Sha256(pub)[0:12]: " + Utils.HEX.encode(key.getMasterVerifyKey().getShortHash()));
                out.flush();
            }
                break;
            case "announce": {
                if (argv.length != 2) {
                    out.println("'announce <index> <key>' needs two arguments");
                    continue;
                }
                final Long index = new Long(argv[0]);
                final MasterSigningKey mk = new MasterSigningKey(Utils.HEX.decode(argv[1]));
                if (index == 0L) {
                    final MasterVerifyKey subkey = mk.getSubKey(index).getMasterVerifyKey();
                    if (!sendAnnounceFirst(mk, subkey, KIT, out)) {
                        out.println("announce failed");
                    }
                } else {
                    final MasterVerifyKey prev = mk.getSubKey(index - 1L).getMasterVerifyKey();
                    final MasterVerifyKey next = mk.getSubKey(index).getMasterVerifyKey();
                    if (!sendAnnounceNext(mk, prev, next, KIT, out)) {
                        out.println("announce failed");
                    }
                }
            }
                break;
            case "revoke":
                if (argv.length != 1) {
                    out.println("'revoke <key>' needs a an argument");
                    continue;
                }
                final MasterSigningKey mk = new MasterSigningKey(Utils.HEX.decode(argv[0]));
                if (!sendOPReturn(mk, KIT, out)) {
                    out.println("revoke failed");
                }
                break;
            case "watch": {
                if (argv.length != 1) {
                    out.println("'watch <key>' needs a an argument");
                    continue;
                }
                final MasterVerifyKey m = new MasterVerifyKey(Utils.HEX.decode(argv[0]));
                if (!WATCHKEYS.contains(m)) {
                    WATCHKEYS.add(m);
                    PARSER.addVerifyKey(m, OPRET_BIRTHDAY);
                }
            }
                break;
            case "scan": {
                scanBlockchain();
            }
            // break; Fall through
            case "listwatch":
                if (!WATCHKEYS.isEmpty()) {
                    out.println("\n");
                    out.println("Watching Keys:");
                    for (final MasterVerifyKey m : WATCHKEYS) {
                        out.println("\tKey: " + m.toString());
                        out.println("\t\tSubKeys:");

                        for (final MasterVerifyKey k : m.subkeys) {
                            out.println("\t\t" + k.toString());
                        }
                        out.println("\n");

                    }
                    out.flush();
                }
                break;
            default:
                out.println("Unknown command. Use 'help' to display available commands.");
                break;
            }
        }
        return;
    }

    public static void main(final String[] args) throws Exception {

        final OptionParser optparser = new OptionParser();
        final OptionSpec<NetworkEnum> net = optparser.accepts("net", "The network to run on").withRequiredArg()
                .ofType(NetworkEnum.class).defaultsTo(NetworkEnum.TEST);

        final OptionSpec<String> name = optparser.accepts("name", "The name of the wallet").withRequiredArg()
                .ofType(String.class).defaultsTo("opretwallet");

        optparser.accepts("help", "Displays program options");
        final OptionSet opts = optparser.parse(args);
        if (opts.has("help")) {
            System.err.println("usage: App [--net=MAIN/TEST/REGTEST] [--name=<name>]");
            optparser.printHelpOn(System.err);
            return;
        }
        if (!opts.has(net)) {
            System.err.println("No net specified, using TestNet!");
        }

        WALLETNAME = name.value(opts);
        PARAMS = net.value(opts).get();

        final boolean chk = PARSER.cryptoSelfTest();
        if (chk) {
            System.err.println("Crypto self test: PASSED");
        } else {
            System.err.println("Crypto self test: FAILED");
            System.exit(-1);
        }

        PARSER.addOPRETECRevokeEventListener((key) -> {
            System.out.println("Revoked Key: " + Utils.HEX.encode(key.toBytes()));
        });

        if (PARAMS.getId().equals(NetworkParameters.ID_REGTEST)) {
        } else if (PARAMS.getId().equals(NetworkParameters.ID_TESTNET)) {
        } else {
            Utils.currentTimeSeconds();
        }

        /*
         * final MasterVerifyKey SVK = SK.getMasterVerifyKey();
         * WATCHKEYS.add(SVK);
         *
         * for (final MasterVerifyKey m : WATCHKEYS) { PARSER.addVerifyKey(m,
         * earliestTime); }
         *
         * scanBlockchain();
         */

        handleConsole();
        if (KIT != null) {
            System.out.println("shutting down");
            KIT.stopAsync();
            KIT.awaitTerminated();
        }
    }

    public static void scanBlockchain() {
        if (!PARSER.needScan()) {
            System.err.println("No scan needed.");
            return;
        }
        if (KIT != null) {
            KIT.rescanBlockchain();
        }
        KIT = new OPRETWalletAppKit(PARAMS, new File("."), WALLETNAME + PARAMS.getId(), PARSER);

        while (PARSER.needScan()) {

            KIT.addListener(new Service.Listener() {
                @Override
                public void failed(final Service.State from, final Throwable failure) {
                    logger.error(failure.getMessage());
                    System.exit(-1);
                }
            }, Threading.SAME_THREAD);

            if (PARAMS.getId().equals(NetworkParameters.ID_REGTEST)) {
                KIT.connectToLocalHost();
            }
            final InputStream is = App.class.getResourceAsStream("/" + PARAMS.getId() + ".checkpoints");
            if (is != null) {
                KIT.setCheckpoints(is);
            }
            KIT.startAsync();

            System.out.println("Please wait for the blockchain to be downloaded!");

            PARSER.willScan();
            try {
                KIT.awaitRunning();
            } catch (final Exception e) {
                System.err.println("Aborting - shutting down");
                // e.printStackTrace();
                KIT.stopAsync();
                KIT.awaitTerminated();
                System.exit(-1);
            }
            // after gathering all the key, replay the blockchain
            if (PARSER.needScan()) {
                System.out.println("Rescanning the blockchain for the newly learned keys!");
                KIT.rescanBlockchain();
                KIT = new OPRETWalletAppKit(PARAMS, new File("."), WALLETNAME + PARAMS.getId(), PARSER);
            }
        }

        KIT.opretwallet().addCoinsReceivedEventListener((wallet1, tx, prevBalance, newBalance) -> {
            final Coin c = tx.getValue(wallet1);

            if (c.isPositive()) {
                System.out.println("-----> coins received: " + tx.getHashAsString());
                System.out.println("received: " + c);
            } else {
                System.out.println("-----> coins sent: " + tx.getHashAsString());
                System.out.println("sent: " + c.negate().toFriendlyString());
            }
        });

        /*
         * wallet.addCoinsSentEventListener(Threading.SAME_THREAD, (wallet1, tx,
         * prevBalance, newBalance) -> { final Coin c = tx.getValue(wallet1);
         *
         * if (c.isPositive()) { System.out.println("-----> coins received: " +
         * tx.getHashAsString()); System.out.println("received: " + c); } else {
         * System.out.println("-----> coins sent: " + tx.getHashAsString());
         * System.out.println("sent: " + c.negate().toFriendlyString()); }
         *
         * });
         *
         * wallet.addKeyChainEventListener(Threading.SAME_THREAD, keys ->
         * System.out.println("new key added"));
         *
         * wallet.addScriptChangeEventListener(Threading.SAME_THREAD, (wallet1,
         * scripts, isAddingScripts) -> System.out.println("new script added"));
         *
         * wallet.addTransactionConfidenceEventListener(Threading.SAME_THREAD,
         * (wallet1, tx) -> { System.out.println("-----> confidence changed: " +
         * tx.getHashAsString()); final TransactionConfidence confidence =
         * tx.getConfidence(); System.out.println("new block depth: " +
         * confidence.getDepthInBlocks()); });
         */
        KIT.opretwallet().allowSpendingUnconfirmedTransactions();
    }

    private static boolean sendAnnounceFirst(MasterSigningKey key, MasterVerifyKey subkey, final OPRETWalletAppKit kit,
            final PrintWriter output) {
        final OPRETWallet wallet = kit.opretwallet();
        final NetworkParameters params = wallet.getNetworkParameters();

        Transaction t = new Transaction(params);
        final Script[] scripts = OPRETECParser.getAnnounceFirstScript(key, subkey);
        t.addOutput(Coin.ZERO, scripts[0]);
        SendRequest request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        request.shuffleOutputs = false;
        try {
            wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            output.println(e.getLocalizedMessage());
            output.flush();
            return false;
        }
        logger.debug("SendRequest {}", request);

        t = new Transaction(params);
        t.addOutput(Coin.ZERO, scripts[1]);
        request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        request.shuffleOutputs = false;
        try {
            wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            output.println(e.getLocalizedMessage());
            output.flush();
            return false;
        }

        logger.debug("SendRequest {}", request);
        return true;
    }

    private static boolean sendAnnounceNext(MasterSigningKey key, MasterVerifyKey prev, MasterVerifyKey next,
            final OPRETWalletAppKit kit, final PrintWriter output) {
        final OPRETWallet wallet = kit.opretwallet();
        final NetworkParameters params = wallet.getNetworkParameters();

        Transaction t = new Transaction(params);
        final Script[] scripts = OPRETECParser.getAnnounceNextScript(key, prev, next);
        t.addOutput(Coin.ZERO, scripts[0]);
        SendRequest request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        request.shuffleOutputs = false;
        try {
            wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            output.println(e.getLocalizedMessage());
            output.flush();
            return false;
        }
        logger.debug("SendRequest {}", request);

        t = new Transaction(params);
        t.addOutput(Coin.ZERO, scripts[1]);
        request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        request.shuffleOutputs = false;
        try {
            wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            output.println(e.getLocalizedMessage());
            output.flush();
            return false;
        }

        logger.debug("SendRequest {}", request);
        return true;
    }

    private static boolean sendOPReturn(MasterSigningKey key, final OPRETWalletAppKit kit, final PrintWriter output) {
        final OPRETWallet wallet = kit.opretwallet();
        final NetworkParameters params = wallet.getNetworkParameters();

        final Transaction t = new Transaction(params);
        final Script script = OPRETECParser.getRevokeScript(key);
        t.addOutput(Coin.ZERO, script);
        final SendRequest request = SendRequest.forTx(t);
        request.ensureMinRequiredFee = true;
        request.shuffleOutputs = false;
        try {
            wallet.sendCoins(request);
        } catch (final InsufficientMoneyException e) {
            output.println(e.getLocalizedMessage());
            output.flush();
            return false;
        }

        logger.debug("SendRequest {}", request);
        return true;
    }
}
