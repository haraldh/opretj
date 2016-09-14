package org.tcpid.opretj.testapp;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.SendRequest;
import org.libsodium.jni.crypto.Hash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tcpid.key.MasterSigningKey;
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

    private static void displayBalance(final OPRETWalletAppKit kit, final PrintWriter out) {
        out.write("Balance: " + kit.wallet().getBalance().toFriendlyString() + "\n");
        out.flush();
    }

    private static void displayHelp(final PrintWriter out) {
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
        final ConsoleReader reader = new ConsoleReader();
        final String[] cmds = { "help", "quit", "exit", "balance", "receive", "empty", "opret" };
        reader.addCompleter(new StringsCompleter(cmds));
        final PrintWriter out = new PrintWriter(reader.getOutput());
        reader.setPrompt("opret> ");
        String line;
        displayHelp(out);
        displayBalance(kit, out);

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
                return;
            case "help":
                displayHelp(out);
                break;
            case "balance":
                displayBalance(kit, out);
                break;
            case "receive":
                final String receiveStr = kit.wallet().freshReceiveAddress().toString();

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
                    final SendRequest request = SendRequest.emptyWallet(Address.fromBase58(kit.params(), argv[0]));
                    try {
                        kit.wallet().sendCoins(request);
                    } catch (final InsufficientMoneyException e) {
                        out.println(e.getLocalizedMessage());
                        out.flush();
                    }
                } catch (final AddressFormatException e) {
                    out.println(e.getLocalizedMessage());
                    out.flush();
                }
                break;
            case "opret":
                sendOPReturn(kit, out);
                break;
            default:
                out.println("Unknown command. Use 'help' to display available commands.");
                break;
            }
        }
    }

    public static void main(final String[] args) throws Exception {

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

        final boolean chk = bs.cryptoSelfTest();
        if (chk) {
            System.err.println("Crypto self test: PASSED");
        } else {
            System.err.println("Crypto self test: FAILED");
            System.exit(-1);
        }

        bs.addOPRETECRevokeEventListener((key) -> {
            System.out.println("Revoked Key: " + Utils.HEX.encode(key.toBytes()));
        });

        long earliestTime;
        if (params.getId().equals(NetworkParameters.ID_REGTEST)) {
            earliestTime = OPRET_BIRTHDAY;
        } else if (params.getId().equals(NetworkParameters.ID_TESTNET)) {
            earliestTime = OPRET_BIRTHDAY;
        } else {
            earliestTime = Utils.currentTimeSeconds();
        }

        bs.addVerifyKey(SK.getMasterVerifyKey(), earliestTime);

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
        final InputStream is = App.class.getResourceAsStream("/" + params.getId() + ".checkpoints");
        if (is != null) {
            kit.setCheckpoints(is);
        }
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
        // wallet.allowSpendingUnconfirmedTransactions();

        handleConsole(kit);

        System.out.println("shutting down");
        kit.stopAsync();
        kit.awaitTerminated();
    }

    private static boolean sendOPReturn(final OPRETWalletAppKit kit, final PrintWriter output) {
        final OPRETWallet wallet = kit.opretwallet();
        final NetworkParameters params = wallet.getNetworkParameters();

        final Transaction t = new Transaction(params);
        final Script script = OPRETECParser.getRevokeScript(SK);
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
