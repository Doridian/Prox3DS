package dspm;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Test applet for Prox3DS's ISO-DEP layer (isodep.c): answers of any length (RX chaining), long
 * commands echoed back (TX chaining) and slow commands (S(WTX)). AID F0334453504D01.
 *
 * 00 01 00 00 Lc data       echo the data
 * 00 02 00 00 Le            Le bytes 00 01 02 ... (Le 00 = 256)
 * 00 03 P1 00               busy for about P1 * 4.4 s on a J3H145, then 9000 (the card sends WTX
 *                           every FWT, about 39 ms, meanwhile)
 * 00 04 00 00 00            "3dspm test applet"
 */
public class TestApplet extends Applet {
    private static final byte[] NAME = { '3', 'd', 's', 'p', 'm', ' ', 't', 'e', 's', 't', ' ', 'a', 'p', 'p', 'l', 'e', 't' };
    private final byte[] scratch = new byte[64];

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new TestApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != 0) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        switch (buf[ISO7816.OFFSET_INS]) {
        case 0x01: {
            short n = apdu.setIncomingAndReceive(), len = n;
            while (n > 0) {
                n = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + len));
                len += n;
            }
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
            return;
        }
        case 0x02: {
            short le = apdu.setOutgoing();
            apdu.setOutgoingLength(le);
            for (short i = 0; i < le; i++) buf[i] = (byte) i;
            apdu.sendBytes((short) 0, le);
            return;
        }
        case 0x03: {
            short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
            for (short i = 0; i < p1; i++)
                for (short k = 0; k < 400; k++) Util.arrayFillNonAtomic(scratch, (short) 0, (short) 64, (byte) k);
            return;
        }
        case 0x04:
            Util.arrayCopyNonAtomic(NAME, (short) 0, buf, (short) 0, (short) NAME.length);
            apdu.setOutgoingAndSend((short) 0, (short) NAME.length);
            return;
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
