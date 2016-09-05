package org.tcpid.key;

import java.util.LinkedList;
import java.util.NoSuchElementException;

public class MasterVerifyKey extends VerifyKey {
    private final LinkedList<VerifyKey> subkeys = new LinkedList<>();

    public MasterVerifyKey(final byte[] key) {
        super(key);
    }

    public void clearSubKeys() {
        subkeys.clear();
    }

    public VerifyKey getValidSubKey() {
        return subkeys.getFirst();
    }

    public void revokeSubKey(final VerifyKey key) {
        final int i = subkeys.indexOf(key);

        if (i == -1) {
            throw new NoSuchElementException("No such subkey");
        }

        subkeys.get(i).setRevoked(true);
        subkeys.remove(i);
    }

    public void setFirstValidSubKey(final VerifyKey key) {
        if (!subkeys.isEmpty()) {
            throw new IndexOutOfBoundsException("Subkey list is not empty");
        }

        subkeys.addLast(key);
    }

    public void setNextValidSubKey(final VerifyKey after, final VerifyKey key) {
        final VerifyKey l = subkeys.getLast();
        if (!l.equals(after)) {
            throw new NoSuchElementException("No such after key, or not last in list");
        }

        subkeys.addLast(key);
    }
}
