package dspm.libuse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import dspm.lib.Counter;
import dspm.lib.LibException;
import dspm.lib.Visitor;

/**
 * Uses the library package dspm.lib (javacard/libtest/lib) for nfcprobe's Java Card VM (issue #19): every
 * test writes what it computed, so the VM and a real card (J3H145) can be compared byte for byte.
 * AID F0334453504D04, package F0334453504D40.
 *
 * 00 10 P1 00 00   test P1 (1..), its bytes
 * 00 11 00 00 00   all tests: per test its number, length and bytes
 */
public class LibUse extends Applet {
    private static final byte TESTS = 9;

    private final byte[] out = new byte[256];
    private short n;
    private final Fast kept; // persistent: an object of a subclass of a library class

    private void b(byte v) { out[n++] = v; }
    private void s(short v) { n = Util.setShort(out, n, v); }
    private void i(int v) { s((short) (v >> 16)); s((short) v); }
    private void z(boolean v) { b(v ? (byte) 1 : (byte) 0); }

    static class Fast extends Counter {
        short extra = 7;
        Fast(short start) { super(start); }
        public short inc() { return (short) (super.inc() + extra); }
        short secret() { return 200; } // not an override: Counter.secret is package-private in dspm.lib
        int sum() { return total + count; } // a protected field of the library class
    }

    static class V implements Visitor {
        short k;
        V(short k) { this.k = k; }
        public short visit(Counter c, short x) { return (short) (c.count * k + x); }
    }

    private LibUse() {
        kept = new Fast((short) 50);
    }

    public static void install(byte[] buf, short off, byte len) {
        new LibUse().register(buf, (short) (off + 1), buf[off]);
    }

    private void test(byte t) {
        switch (t) {
        case 1: // static methods
            s(Counter.twice((short) 21));
            i(Counter.mix(0x01020304, (short) 0x55));
            break;
        case 2: { // static fields: read, write, a library's array, a reference
            b(Counter.sb);
            s(Counter.ss);
            i(Counter.si);
            Counter.table();
            s((short) Counter.table.length);
            b(Counter.table[1]);
            Counter.ss++;
            Counter.si += 0x100;
            Counter.table[2]++;
            s(Counter.ss);
            i(Counter.si);
            b(Counter.table[2]);
            z(Counter.sref == null);
            Counter.sref = out;
            z(Counter.sref == out);
            Counter.sref = null;
            break;
        }
        case 3: { // a library object: fields, virtual methods
            Counter c = new Counter((short) 10);
            s(c.step());
            s(c.step());
            s(c.count);
            i(c.total());
            b(c.hidden());
            s(c.callSecret());
            Counter m = Counter.make((short) -4);
            s(m.step());
            c.count = 1000;
            s(c.step());
            break;
        }
        case 4: { // a subclass in this package: overriding, super calls, inherited and own fields
            Fast f = new Fast((short) 1);
            s(f.step());
            s(f.step());
            s(f.count);
            i(f.total());
            i(f.sum());
            s(f.extra);
            b(f.hidden());
            s(f.callSecret()); // 100: the library's own secret()
            s(f.secret());     // 200: this package's
            Counter c = f;
            s(c.inc());
            break;
        }
        case 5: { // instanceof / checkcast against library classes and interfaces
            Object f = new Fast((short) 0), v = new V((short) 1), c = new Counter((short) 0);
            z(f instanceof Counter);
            z(c instanceof Fast);
            z(v instanceof Visitor);
            z(f instanceof Visitor);
            Counter k = (Counter) f;
            s(k.count);
            try {
                Visitor x = (Visitor) c;
                s(x.visit(k, (short) 1));
            } catch (ClassCastException e) {
                b((byte) 0xCC);
            }
            break;
        }
        case 6: { // interfaces both ways: the library calls this package's class, this package calls through it
            V v = new V((short) 3);
            Counter c = new Counter((short) 5);
            s(Counter.apply(v, c, (short) 2));
            Visitor w = v;
            s(w.visit(new Fast((short) 4), (short) 1));
            s(Counter.apply(w, kept, (short) 0));
            break;
        }
        case 7: // exceptions: a library exception class, an API one thrown by library code
            try {
                Counter.thrower((short) 0x1234);
            } catch (LibException e) {
                s(e.getReason());
            }
            try {
                Counter.thrower((short) 0x2345);
            } catch (CardRuntimeException e) {
                s(e.getReason());
                z(e instanceof LibException);
            }
            try {
                Counter.rethrow((short) 0x3456);
            } catch (LibException e) {
                b((byte) 1);
            } catch (CardRuntimeException e) {
                s(e.getReason());
            }
            break;
        case 8: { // a transaction on library statics and a library object
            short ss = Counter.ss;
            Counter.table();
            byte t0 = Counter.table[0];
            short k = kept.count;
            JCSystem.beginTransaction();
            Counter.ss = 999;
            Counter.table[0] = 99;
            kept.count = 999;
            JCSystem.abortTransaction();
            z(Counter.ss == ss);
            z(Counter.table[0] == t0);
            z(kept.count == k);
            break;
        }
        case 9: // persistent state across sessions: the kept object and the library statics move on each time
            s(kept.step());
            i(kept.total());
            s(Counter.calls());
            s(Counter.ss);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        n = 0;
        switch (buf[ISO7816.OFFSET_INS]) {
        case 0x10:
            test(buf[ISO7816.OFFSET_P1]);
            break;
        case 0x11:
            for (byte t = 1; t <= TESTS; t++) {
                short at = n;
                n += 2;
                test(t);
                out[at] = t;
                out[(short) (at + 1)] = (byte) (n - at - 2);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        Util.arrayCopyNonAtomic(out, (short) 0, buf, (short) 0, n);
        apdu.setOutgoingAndSend((short) 0, n);
    }
}
