package dspm.vmtest;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.UserException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Java Card VM conformance applet for Prox3DS's VM (issue #19): every test writes what it computed, so
 * the Python VM (tools/jcvm), the C VM (jcvm.c) and a real card (J3H145) can be compared byte for byte.
 * AID F0334453504D02.
 *
 * 00 10 P1 00 00   test P1 (1..), its bytes
 * 00 11 00 00 00   all tests: per test its number, length and bytes
 * 00 12 00 00 00   the transient arrays: 2 bytes (CLEAR_ON_RESET, CLEAR_ON_DESELECT), then both set to 5
 */
public class VmTest extends Applet {
    static byte sb = -3;
    static short ss = 1234;
    static int si = 0x12345678;
    static boolean sz = true;
    static byte[] sbytes = { 1, 2, 3, (byte) 0x80 };
    static short[] sshorts = { -1, 300, 0x7FFF };
    static int[] sints = { -2, 0x10000 };
    static Object sref;

    private final byte[] out = new byte[256];
    private short n;
    private int fi = -5;
    private short fs = 7;
    private byte fb = -1;
    private boolean fz;
    private Shape[] shapes;
    private final byte[] persistent = new byte[8];
    private final byte[] tReset, tDeselect;
    private final OwnerPIN pin = new OwnerPIN((byte) 3, (byte) 8);
    private final MessageDigest sha1, sha256;

    // --- helpers: results into out[] ---

    private void b(byte v) { out[n++] = v; }
    private void s(short v) { n = Util.setShort(out, n, v); }
    private void i(int v) { s((short) (v >> 16)); s((short) v); }
    private void z(boolean v) { b(v ? (byte) 1 : (byte) 0); }

    // --- classes for the object tests ---

    abstract static class Shape {
        short id;
        abstract short area();
        short twice() { return (short) (area() * 2); }
        short kind() { return 1; }
    }

    interface Named {
        byte tag();
        short tagged(short x);
    }

    static class Rect extends Shape implements Named {
        short w, h;
        Rect(short w, short h) { this.w = w; this.h = h; id = 10; }
        short area() { return (short) (w * h); }
        short kind() { return (short) (super.kind() + 1); }
        public byte tag() { return 'R'; }
        public short tagged(short x) { return (short) (x + w); }
    }

    static class Square extends Rect {
        int big = 0x01020304;
        Square(short s) { super(s, s); id = 20; }
        short kind() { return (short) (super.kind() * 10); }
        public byte tag() { return 'S'; }
    }

    static class Boom extends UserException {
        Boom(short r) { super(r); }
    }

    private VmTest() {
        tReset = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_RESET);
        tDeselect = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        pin.update(new byte[] { 1, 2, 3, 4 }, (short) 0, (byte) 4);
        sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        shapes = new Shape[] { new Rect((short) 3, (short) 4), new Square((short) 5) };
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new VmTest().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    // --- tests ---

    private void shorts() {
        short a = -32768, m1 = -1, x = -1000, y = 7;
        s((short) (a / m1));
        s((short) (a % m1));
        s((short) (x / y));
        s((short) (x % y));
        s((short) (x >> 3));
        s((short) (x >>> 3));
        s((short) (x << 9));
        s((short) -a);
        b((byte) 0x1FF);
        s((short) (y * 5000));
        s((short) (x & 0x0FF0));
        s((short) (x | 3));
        s((short) (x ^ 0x5555));
        byte bb = (byte) x;
        s(bb);
        s((short) (x >>> 17));
        s((short) (y << 17));
    }

    private void ints() {
        int a = 0x7FFFFFFF, b = -7, c = Integer_MIN();
        i(a + 1);
        i(a * 3);
        i(b / 2);
        i(b % 2);
        i(c / -1);
        i(c % -1);
        i(b >> 1);
        i(b >>> 1);
        i(b << 30);
        i(-c);
        s((short) a);
        b((byte) a);
        i(fi * fi);
        int k = 5;
        k += 1000000;
        i(k);
        k++;
        k--;
        k -= 200;
        i(k);
        z(a > b);
        z(c < b);
        z(b == -7);
        i(sints[0] + sints[1]);
        sints[1] <<= 1;
        i(sints[1]);
        sints[1] >>= 1;
    }

    private static int Integer_MIN() { return 0x80000000; }

    private short sw(short v) {
        switch (v) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        case 4: return 40;
        default: return -1;
        }
    }

    private short lk(short v) {
        switch (v) {
        case -500: return 1;
        case 7: return 2;
        case 30000: return 3;
        default: return 4;
        }
    }

    private short isw(int v) {
        switch (v) {
        case 100000: return 1;
        case -3: return 2;
        case 0x7FFFFFFF: return 3;
        default: return 0;
        }
    }

    private short itab(int v) {
        switch (v) {
        case 0: return 5;
        case 1: return 6;
        case 2: return 7;
        case 3: return 8;
        default: return 9;
        }
    }

    private void switches() {
        for (short v = 0; v <= 5; v++) s(sw(v));
        s(lk((short) -500));
        s(lk((short) 7));
        s(lk((short) 30000));
        s(lk((short) 8));
        s(isw(100000));
        s(isw(-3));
        s(isw(0x7FFFFFFF));
        s(isw(4));
        for (int v = -1; v <= 4; v++) s(itab(v));
    }

    private short thrower(short how) throws Boom {
        byte[] arr = new byte[2];
        Object o = null;
        switch (how) {
        case 0: return arr[5];
        case 1: return ((byte[]) o)[0];
        case 2: return (short) (10 / (how - 2));
        case 3: throw new Boom((short) 0x1234);
        case 4: ISOException.throwIt((short) 0x6A88);
        case 5: Object x = new byte[1]; return ((short[]) x)[0];
        case 6: return (short) new byte[(short) (how - 10)].length;
        }
        return 0;
    }

    private void exceptions() {
        for (short k = 0; k <= 7; k++) {
            short r = 0;
            try {
                r = thrower(k);
            } catch (ArrayIndexOutOfBoundsException e) {
                r = 100;
            } catch (NullPointerException e) {
                r = 101;
            } catch (ArithmeticException e) {
                r = 102;
            } catch (Boom e) {
                r = (short) (e.getReason() + 1);
            } catch (ISOException e) {
                r = e.getReason();
            } catch (ClassCastException e) {
                r = 103;
            } catch (RuntimeException e) {
                r = 104;
            } finally {
                r += 1000;
            }
            s(r);
        }
        short depth = 0;
        try {
            try {
                ISOException.throwIt((short) 0x6400);
            } finally {
                depth = 1;
            }
        } catch (ISOException e) {
            depth += 2;
        }
        s(depth);
    }

    private void objects() {
        for (short k = 0; k < shapes.length; k++) {
            Shape sh = shapes[k];
            s(sh.area());
            s(sh.twice());
            s(sh.kind());
            s(sh.id);
            Named nm = (Named) sh;
            b(nm.tag());
            s(nm.tagged((short) 100));
            z(sh instanceof Square);
            z(sh instanceof Named);
        }
        Square sq = (Square) shapes[1];
        i(sq.big);
        sq.big += 0x10;
        i(sq.big);
        Object o = shapes;
        z(o instanceof Shape[]);
        z(o instanceof Object[]);
        z(o instanceof Rect[]);
        Object ba = sbytes;
        z(ba instanceof byte[]);
        z(ba instanceof short[]);
        boolean cast;
        try {
            Rect[] r = (Rect[]) o;
            cast = r != null;
        } catch (ClassCastException e) {
            cast = false;
        }
        z(cast);
        b(sb);
        s(ss);
        i(si);
        z(sz);
        b(sbytes[3]);
        s(sshorts[0]);
        s(sshorts[2]);
        sb++;
        ss += 2;
        si ^= -1;
        sz = !sz;
        b(sb);
        s(ss);
        i(si);
        z(sz);
        z(sref == null);
        b(fb);
        s(fs);
        i(fi);
        z(fz);
    }

    private void transactions() {
        Util.arrayFillNonAtomic(persistent, (short) 0, (short) 8, (byte) 1);
        fs = 7;
        JCSystem.beginTransaction();
        persistent[0] = 9;
        fs = 99;
        Util.arrayFillNonAtomic(persistent, (short) 4, (short) 2, (byte) 5); // not undone
        b(JCSystem.getTransactionDepth());
        JCSystem.abortTransaction();
        b(persistent[0]);
        b(persistent[4]);
        s(fs);
        JCSystem.beginTransaction();
        persistent[1] = 3;
        JCSystem.commitTransaction();
        b(persistent[1]);
        b(JCSystem.getTransactionDepth());
        b(JCSystem.isTransient(tReset));
        b(JCSystem.isTransient(tDeselect));
        b(JCSystem.isTransient(persistent));
    }

    private void utilTest() {
        byte[] a = { 1, (byte) 0x80, 3 }, c = { 1, 1, 3 };
        b(Util.arrayCompare(a, (short) 0, c, (short) 0, (short) 3));
        b(Util.arrayCompare(c, (short) 0, a, (short) 0, (short) 3));
        b(Util.arrayCompare(a, (short) 0, a, (short) 0, (short) 3));
        s(Util.makeShort((byte) 0x80, (byte) 0xFF));
        s(Util.getShort(a, (short) 1));
        byte[] t = new byte[6];
        s(Util.arrayCopy(a, (short) 0, t, (short) 2, (short) 3));
        s(Util.arrayCopyNonAtomic(t, (short) 2, t, (short) 3, (short) 3));
        for (short k = 0; k < 6; k++) b(t[k]);
        s(Util.setShort(t, (short) 0, (short) 0xABCD));
        b(t[0]);
        b(t[1]);
        short e = 0;
        try {
            Util.arrayCopy(a, (short) 2, t, (short) 0, (short) 2);
        } catch (ArrayIndexOutOfBoundsException x) {
            e = 1;
        }
        s(e);
    }

    private void pinTest() {
        byte[] good = { 1, 2, 3, 4 }, bad = { 1, 2, 3, 5 };
        z(pin.check(bad, (short) 0, (byte) 4));
        b(pin.getTriesRemaining());
        z(pin.isValidated());
        z(pin.check(good, (short) 0, (byte) 4));
        b(pin.getTriesRemaining());
        z(pin.isValidated());
        pin.reset();
        z(pin.isValidated());
        z(pin.check(good, (short) 0, (byte) 3));
        b(pin.getTriesRemaining());
        pin.resetAndUnblock();
        b(pin.getTriesRemaining());
    }

    private void aidTest() {
        AID me = JCSystem.getAID();
        byte[] t = new byte[16];
        b(me.getBytes(t, (short) 0));
        for (short k = 0; k < 7; k++) b(t[k]);
        z(me.equals(t, (short) 0, (byte) 7));
        z(me.partialEquals(t, (short) 0, (byte) 5));
        z(me.equals(JCSystem.lookupAID(t, (short) 0, (byte) 7)));
        t[6] = 9;
        z(JCSystem.lookupAID(t, (short) 0, (byte) 7) == null);
    }

    private void digests() {
        byte[] m = new byte[100];
        for (short k = 0; k < 100; k++) m[k] = (byte) k;
        sha1.update(m, (short) 0, (short) 30);
        n += sha1.doFinal(m, (short) 30, (short) 70, out, n);
        n += sha256.doFinal(m, (short) 0, (short) 100, out, n);
        b(sha1.getLength());
        b(sha256.getAlgorithm());
    }

    private void stackOps() {
        // dup_x / swap_x / dup2 from compound assignments on arrays and int fields
        short[] sa = { 5, 6 };
        int[] ia = { 1, 2 };
        short k = 0;
        sa[k++] += 10;
        ia[k--] *= 7;
        fi = fi++ + ++fi;
        s(sa[0]);
        s(sa[1]);
        i(ia[1]);
        i(fi);
        s(k);
        int big = (sa[0] * 1000) + ia[1];
        i(big);
        fi = -5;
    }

    private boolean test(byte t) {
        switch (t) {
        case 1: shorts(); return true;
        case 2: ints(); return true;
        case 3: switches(); return true;
        case 4: exceptions(); return true;
        case 5: objects(); return true;
        case 6: transactions(); return true;
        case 7: utilTest(); return true;
        case 8: pinTest(); return true;
        case 9: aidTest(); return true;
        case 10: digests(); return true;
        case 11: stackOps(); return true;
        }
        return false;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        n = 0;
        switch (buf[ISO7816.OFFSET_INS]) {
        case 0x10:
            if (!test(buf[ISO7816.OFFSET_P1])) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            break;
        case 0x11:
            for (byte t = 1; t <= 11; t++) {
                if (t == 10) continue; // digests: on their own (the total stays under 256)
                short at = n;
                n += 2;
                test(t);
                out[at] = t;
                out[(short) (at + 1)] = (byte) (n - at - 2);
            }
            break;
        case 0x12:
            b(tReset[0]);
            b(tDeselect[0]);
            tReset[0] = 5;
            tDeselect[0] = 5;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        Util.arrayCopyNonAtomic(out, (short) 0, buf, (short) 0, n);
        apdu.setOutgoingAndSend((short) 0, n);
    }
}
