package org.tcpid.opretj;


import static com.google.common.base.Preconditions.checkState;

import java.io.File;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletProtobufSerializer.WalletFactory;

public class OPRETWalletAppKit extends WalletAppKit {
    // private final Logger logger = LoggerFactory.getLogger(OPRETWallet.class);
    private final OPRETHandlerInterface opbs;

    public OPRETWalletAppKit(NetworkParameters params, File directory, String filePrefix, OPRETHandlerInterface bs) {
        super(params, directory, filePrefix);
        opbs = bs;
        walletFactory = new WalletFactory() {
            @Override
            public Wallet create(NetworkParameters params, KeyChainGroup keyChainGroup) {
                return new OPRETWallet(params, keyChainGroup, opbs);
            }
        };
    }

    @Override
    protected void onSetupCompleted() {
        final OPRETWallet wallet = opretwallet();
        opbs.addOPRETChangeEventListener(Threading.USER_THREAD, wallet);
        // TODO: remove
        wallet.reset();
        peerGroup().addBlocksDownloadedEventListener(wallet);
    }

    public OPRETWallet opretwallet() throws RuntimeException, IllegalStateException {
        checkState((state() == State.STARTING) || (state() == State.RUNNING), "Cannot call until startup is complete");
        final Wallet w = wallet();
        if (w instanceof OPRETWallet) {
            return (OPRETWallet) w;
        } else {
            throw new RuntimeException("wallet != OPTRETWallet");
        }
    }

    @Override
    protected BlockStore provideBlockStore(File file) throws BlockStoreException {
    	// TODO: save state
        if (params.getId().equals(NetworkParameters.ID_REGTEST) || params.getId().equals(NetworkParameters.ID_TESTNET)) {
            file.deleteOnExit();
        }
        return new SPVBlockStore(params, file);
    }
}