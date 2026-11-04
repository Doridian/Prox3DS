package dspm.lib;

import javacard.framework.CardRuntimeException;

/**
 * A library package (no applet) for Prox3DS's Java Card VM (issue #19): dspm.libuse calls into it across
 * packages, so every kind of reference to another CAP package gets used. AID F0334453504D30.
 */
public class Counter {
    public static byte sb = 5;
    public static short ss = 300;
    public static int si = 0x01020304;
    public static byte[] table; // a library may not initialize static arrays: table() makes it
    public static Object sref;
    static short calls; // package-private: only this package's code touches it

    public short count;
    protected int total;
    byte hidden = 3;

    public Counter(short start) {
        count = start;
    }

    public short step() {
        calls++;
        count += inc();
        total += count;
        return count;
    }

    public short inc() {
        return 1;
    }

    // package-private: a method of the same name in another package's subclass doesn't override it
    short secret() {
        return 100;
    }

    public short callSecret() {
        return secret();
    }

    public byte hidden() {
        return hidden;
    }

    public int total() {
        return total;
    }

    public static byte[] table() {
        if (table == null) table = new byte[] { 9, 8, 7 };
        return table;
    }

    public static short twice(short x) {
        return (short) (x * 2);
    }

    public static int mix(int a, short b) {
        return (a << 4) ^ b;
    }

    public static Counter make(short start) {
        return new Counter(start);
    }

    public static short calls() {
        return calls;
    }

    public static short apply(Visitor v, Counter c, short x) {
        return v.visit(c, x);
    }

    public static void thrower(short reason) {
        throw new LibException(reason);
    }

    public static void rethrow(short reason) {
        CardRuntimeException.throwIt(reason);
    }
}
