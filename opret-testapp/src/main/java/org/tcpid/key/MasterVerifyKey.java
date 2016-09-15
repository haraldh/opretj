package org.tcpid.key;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

import org.tcpid.opretj.OPRETTransaction;

import com.google.common.primitives.Bytes;

public class MasterVerifyKey extends VerifyKey {
    // FIXME: make private again
    public final LinkedList<MasterVerifyKey> subkeys = new LinkedList<>();

    public MasterVerifyKey(final byte[] key) {
        super(key);
    }

    public void clearSubKeys() {
        subkeys.clear();
    }

    public MasterVerifyKey getSubKeybyHash(List<Byte> subpkhash) {
        for (final MasterVerifyKey k : subkeys) {
            if (Arrays.equals(k.getShortHash(), Bytes.toArray(subpkhash))) {
                return k;
            }
        }
        return null;
    }

    public MasterVerifyKey getValidSubKey() {
        for (final MasterVerifyKey k : subkeys) {
            if (!k.isRevoked()) {
                return k;
            }
        }
        return null;
    }

    public void revokeSubKey(final VerifyKey key) {
        final int i = subkeys.indexOf(key);

        if (i == -1) {
            throw new NoSuchElementException("No such subkey");
        }
    }

    public void setFirstValidSubKey(final MasterVerifyKey key, final OPRETTransaction t1, final OPRETTransaction t2) {
        if (!subkeys.isEmpty()) {
            throw new IndexOutOfBoundsException("Subkey list is not empty");
        }
        subkeys.addLast(key);
        key.setMasterkey(this);
    }

    public void setNextValidSubKey(final MasterVerifyKey after, final MasterVerifyKey key, OPRETTransaction t1,
            OPRETTransaction t2) {

        if (subkeys.contains(key)) {
            throw new NoSuchElementException("Already in");
        }

        final int i = subkeys.indexOf(after);

        if (i == -1) {
            throw new NoSuchElementException("No such subkey");
        }

        subkeys.add(i + 1, key);
        key.setMasterkey(this);
    }
}
