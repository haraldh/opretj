package org.tcpid.key;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

import org.tcpid.opretj.OPRETTransaction;

import com.google.common.primitives.Bytes;

public class MasterVerifyKey extends VerifyKey {
    private final LinkedList<MasterVerifyKey> subkeys = new LinkedList<>();

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
        return subkeys.getFirst();
    }

    public void revokeSubKey(final MasterVerifyKey key) {
        final int i = subkeys.indexOf(key);

        if (i == -1) {
            throw new NoSuchElementException("No such subkey");
        }

        subkeys.get(i).setRevoked(true);
        subkeys.remove(i);
    }

    public void setFirstValidSubKey(final MasterVerifyKey key, final OPRETTransaction t1, final OPRETTransaction t2) {
        if (!subkeys.isEmpty()) {
            throw new IndexOutOfBoundsException("Subkey list is not empty");
        }

        subkeys.addLast(key);
    }

    public void setNextValidSubKey(final MasterVerifyKey after, final MasterVerifyKey key, OPRETTransaction t1,
            OPRETTransaction t2) {
        final MasterVerifyKey l = subkeys.getLast();
        if (!l.equals(after)) {
            throw new NoSuchElementException("No such after key, or not last in list");
        }

        subkeys.addLast(key);
    }
}
