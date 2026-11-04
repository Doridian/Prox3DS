package dspm.cprobe;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * Crypto ground truth for Prox3DS's Java Card VM: runs Cipher / Signature / MessageDigest /
 * KeyBuilder with the keys and data it is given, so a real card (J3H145) and the VM can be compared.
 * AID F0334453504D03. Errors: CryptoException 64rr, APDUException 67sr, other CardRuntimeException 66sr,
 * AIOOBE 65s1, NPE 65s2, other exceptions 65s3 (r = reason, s = stage: 1 receive, 2 work, 3 send).
 *
 * 80 30 P1 P2      getInstance(alg, false) for alg 1..P2, one byte each: 0 = ok, else the CryptoException
 *                  reason (FF = other exception). P1: 0 Cipher, 1 Signature, 2 MessageDigest, 3 RandomData,
 *                  4 KeyAgreement
 * 80 31 00 P2 key  Cipher: alg mode | key | ivLen iv | split(2) input. update(input[0..split]) then
 *                  doFinal(rest); out: updateLen(2) update final. P2 & 1: a second doFinal of the whole
 *                  input after (no init), appended as len(2) out
 * 80 32 00 P2 key  Signature: alg mode | key | ivLen iv | split(2) input; sign -> update + sign
 *                  out (P2 & 1: sign again, appended); verify: input = msgLen(2) msg sig -> 1 byte
 * 80 33 00 P2      MessageDigest: alg split(2) input -> digest (P2 & 1: doFinal of nothing after, appended)
 * 80 34 P1 00      extended APDUs: incoming length(2), offsetCdata(2), in / out block size(2 each),
 *                  protocol(1), buffer length(2), then the data back (P1 = 1: only the header; P1 = 2:
 *                  receiveBytes(offsetCdata) for the next blocks instead of 0)
 * 80 35 P1 P2      RandomData P1, P2 bytes (length checked only)
 * 80 36 P1 00 b2   KeyBuilder.buildKey(P1, bits, false): size(2) type(1) initialized(1), after setKey(00..)
 *                  initialized(1) getKey
 * 80 37 00 00     KeyAgreement: alg | private key | public point -> secret
 * 80 38 P1 00 b2   KeyPair(P1, bits).genKeyPair(): verify(1) of a signature over 32 bytes (in) made with
 *                  it, then the public key (RSA modulus / EC W). EC: a curve after the 32 bytes is set first
 * key = keyType(1) keyBits(2) keyLen(2) key; RSA: modLen(2) modulus exponent; RSA CRT: P Q DP1 DQ1 PQ,
 * each len(2) value; EC (FP): p a b G r W-or-S, each len(2) value (cofactor 1). A CryptoException while
 * making the key: 64kr, k = 1 buildKey, 2 setKey / modulus / P / field, 3 exponent / Q / A, 4.. the rest.
 */
public class CryptoProbe extends Applet implements ExtendedLength {
    private final byte[] in = new byte[1100];
    private final byte[] out = new byte[1100];
    private short n;
    private short p;
    private short kstage;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoProbe().register();
    }

    private short u8() {
        return (short) (in[p++] & 0xFF);
    }

    private short u16() {
        short v = Util.getShort(in, p);
        p += 2;
        return v;
    }

    private Key key() {
        byte type = in[p++];
        short bits = u16();
        short len = u16();
        short end = (short) (p + len);
        kstage = 0x10;
        Key k = KeyBuilder.buildKey(type, bits, false);
        kstage = 0x20;
        if (k instanceof DESKey) ((DESKey) k).setKey(in, p);
        else if (k instanceof AESKey) ((AESKey) k).setKey(in, p);
        else if (k instanceof HMACKey) ((HMACKey) k).setKey(in, p, len);
        else if (k instanceof RSAPublicKey) {
            short ml = u16();
            ((RSAPublicKey) k).setModulus(in, p, ml);
            kstage = 0x30;
            ((RSAPublicKey) k).setExponent(in, (short) (p + ml), (short) (end - p - ml));
        } else if (k instanceof RSAPrivateKey) {
            short ml = u16();
            ((RSAPrivateKey) k).setModulus(in, p, ml);
            kstage = 0x30;
            ((RSAPrivateKey) k).setExponent(in, (short) (p + ml), (short) (end - p - ml));
        } else if (k instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey c = (RSAPrivateCrtKey) k;
            for (byte i = 0; i < 5; i++) {
                short l = u16();
                switch (i) {
                case 0: c.setP(in, p, l); break;
                case 1: c.setQ(in, p, l); break;
                case 2: c.setDP1(in, p, l); break;
                case 3: c.setDQ1(in, p, l); break;
                case 4: c.setPQ(in, p, l); break;
                }
                p += l;
                kstage += 0x10;
            }
        } else if (k instanceof ECKey) {
            ECKey e = (ECKey) k;
            for (byte i = 0; i < 6; i++) {
                short l = u16();
                switch (i) {
                case 0: e.setFieldFP(in, p, l); break;
                case 1: e.setA(in, p, l); break;
                case 2: e.setB(in, p, l); break;
                case 3: e.setG(in, p, l); break;
                case 4: e.setR(in, p, l); e.setK((short) 1); break;
                case 5:
                    if (k instanceof ECPublicKey) ((ECPublicKey) k).setW(in, p, l);
                    else ((ECPrivateKey) k).setS(in, p, l);
                    break;
                }
                p += l;
                kstage += 0x10;
            }
        }
        kstage = 0;
        p = end;
        return k;
    }

    private void probe(byte what, byte max) {
        for (short a = 1; a <= max; a++) {
            byte r = 0;
            try {
                switch (what) {
                case 0: Cipher.getInstance((byte) a, false); break;
                case 1: Signature.getInstance((byte) a, false); break;
                case 2: MessageDigest.getInstance((byte) a, false); break;
                case 3: RandomData.getInstance((byte) a); break;
                case 4: KeyAgreement.getInstance((byte) a, false); break;
                }
            } catch (CryptoException e) {
                r = (byte) e.getReason();
            } catch (Exception e) {
                r = (byte) 0xFF;
            }
            out[n++] = r;
        }
        JCSystem.requestObjectDeletion();
    }

    private void cipher(byte flags) {
        byte alg = in[p++];
        byte mode = in[p++];
        Key k = key();
        short ivl = u8();
        short iv = p;
        p += ivl;
        short split = u16();
        short len = (short) (n - p);
        Cipher c = Cipher.getInstance(alg, false);
        if (ivl == 0) c.init(k, mode);
        else c.init(k, mode, in, iv, ivl);
        short u = c.update(in, p, split, out, (short) 2);
        Util.setShort(out, (short) 0, u);
        short o = (short) (2 + u);
        o += c.doFinal(in, (short) (p + split), (short) (len - split), out, o);
        if ((flags & 1) != 0) {
            short at = o;
            o += 2;
            o += c.doFinal(in, p, len, out, o);
            Util.setShort(out, at, (short) (o - at - 2));
        }
        n = o;
    }

    private void signature(byte flags) {
        byte alg = in[p++];
        byte mode = in[p++];
        Key k = key();
        short ivl = u8();
        short iv = p;
        p += ivl;
        short split = u16();
        short len = (short) (n - p);
        Signature s = Signature.getInstance(alg, false);
        if (ivl == 0) s.init(k, mode);
        else s.init(k, mode, in, iv, ivl);
        if (mode == Signature.MODE_VERIFY) {
            short ml = u16();
            s.update(in, p, split);
            boolean ok = s.verify(in, (short) (p + split), (short) (ml - split), in, (short) (p + ml),
                    (short) (len - 2 - ml));
            out[0] = (byte) (ok ? 1 : 0);
            n = 1;
            return;
        }
        s.update(in, p, split);
        short o = s.sign(in, (short) (p + split), (short) (len - split), out, (short) 0);
        if ((flags & 1) != 0) o += s.sign(in, p, len, out, o);
        n = o;
    }

    private void agree() {
        byte alg = in[p++];
        Key k = key();
        short len = (short) (n - p);
        KeyAgreement a = KeyAgreement.getInstance(alg, false);
        a.init((PrivateKey) k);
        n = a.generateSecret(in, p, len, out, (short) 0);
    }

    // KeyPair(alg, bits).genKeyPair(), then a signature over in[] with the private key checked with the
    // public one: 1 byte verify result, then the public key (RSA: modulus, EC: W)
    private void pair(byte alg) {
        short bits = Util.getShort(in, (short) 0);
        KeyPair kp = new KeyPair(alg, bits);
        if (n > 32) { // a curve after the 32 bytes: p a b G r (each len(2) value) on both keys
            p = 32;
            for (byte i = 0; i < 5; i++) {
                short l = u16();
                for (byte w = 0; w < 2; w++) {
                    ECKey e = (ECKey) (w == 0 ? (Object) kp.getPublic() : (Object) kp.getPrivate());
                    switch (i) {
                    case 0: e.setFieldFP(in, p, l); break;
                    case 1: e.setA(in, p, l); break;
                    case 2: e.setB(in, p, l); break;
                    case 3: e.setG(in, p, l); break;
                    case 4: e.setR(in, p, l); e.setK((short) 1); break;
                    }
                }
                p += l;
            }
        }
        kp.genKeyPair();
        Signature s = Signature.getInstance(alg == KeyPair.ALG_EC_FP ? Signature.ALG_ECDSA_SHA_256
                : Signature.ALG_RSA_SHA_256_PKCS1, false);
        s.init(kp.getPrivate(), Signature.MODE_SIGN);
        short sl = s.sign(in, (short) 0, (short) 32, out, (short) 600);
        s.init(kp.getPublic(), Signature.MODE_VERIFY);
        out[0] = (byte) (s.verify(in, (short) 0, (short) 32, out, (short) 600, sl) ? 1 : 0);
        if (alg == KeyPair.ALG_EC_FP) n = (short) (1 + ((ECPublicKey) kp.getPublic()).getW(out, (short) 1));
        else n = (short) (1 + ((RSAPublicKey) kp.getPublic()).getModulus(out, (short) 1));
    }

    private void digest(byte flags) {
        byte alg = in[p++];
        short split = u16();
        short len = (short) (n - p);
        MessageDigest d = MessageDigest.getInstance(alg, false);
        d.update(in, p, split);
        short o = d.doFinal(in, (short) (p + split), (short) (len - split), out, (short) 0);
        if ((flags & 1) != 0) o += d.doFinal(in, p, (short) 0, out, o);
        n = o;
    }

    private void keys(byte type) {
        Key k = KeyBuilder.buildKey(type, Util.getShort(in, (short) 0), false);
        Util.setShort(out, (short) 0, k.getSize());
        out[2] = k.getType();
        out[3] = (byte) (k.isInitialized() ? 1 : 0);
        n = 4;
        Util.arrayFillNonAtomic(in, (short) 0, (short) 64, (byte) 0);
        if (k instanceof DESKey) ((DESKey) k).setKey(in, (short) 0);
        else if (k instanceof AESKey) ((AESKey) k).setKey(in, (short) 0);
        else if (k instanceof HMACKey) ((HMACKey) k).setKey(in, (short) 0, (short) 32);
        out[n++] = (byte) (k.isInitialized() ? 1 : 0);
        if (k instanceof DESKey) n += ((DESKey) k).getKey(out, n);
        else if (k instanceof AESKey) n += ((AESKey) k).getKey(out, n);
        else if (k instanceof HMACKey) n += ((HMACKey) k).getKey(out, n);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short stage = 0x10;
        kstage = 0;
        try {
            short got = apdu.setIncomingAndReceive();
            short cd = apdu.getOffsetCdata();
            n = 0;
            short at = cd;
            while (got > 0) {
                n = Util.arrayCopyNonAtomic(buf, at, in, n, got);
                at = p1 == 2 ? cd : (short) 0;
                got = apdu.receiveBytes(at);
            }
            short inLen = n;
            p = 0;
            stage = 0x20;
            switch (ins) {
            case 0x30: n = 0; probe(p1, p2); break;
            case 0x31: cipher(p2); break;
            case 0x32: signature(p2); break;
            case 0x33: digest(p2); break;
            case 0x37: agree(); break;
            case 0x38: pair(p1); break;
            case 0x34:
                Util.setShort(out, (short) 0, apdu.getIncomingLength());
                Util.setShort(out, (short) 2, cd);
                Util.setShort(out, (short) 4, APDU.getInBlockSize());
                Util.setShort(out, (short) 6, APDU.getOutBlockSize());
                out[8] = APDU.getProtocol();
                Util.setShort(out, (short) 9, (short) buf.length);
                n = 11;
                if (p1 != 1) n = Util.arrayCopyNonAtomic(in, (short) 0, out, n, inLen);
                break;
            case 0x35:
                RandomData.getInstance(p1).generateData(out, (short) 0, (short) (p2 & 0xFF));
                n = (short) (p2 & 0xFF);
                break;
            case 0x36: keys(p1); break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            stage = 0x30;
            apdu.setOutgoing();
            apdu.setOutgoingLength(n);
            apdu.sendBytesLong(out, (short) 0, n);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6400 | kstage | e.getReason()));
        } catch (ISOException e) {
            throw e;
        } catch (APDUException e) {
            ISOException.throwIt((short) (0x6700 | stage | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (0x6600 | stage | e.getReason()));
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt((short) (0x6501 | stage));
        } catch (NullPointerException e) {
            ISOException.throwIt((short) (0x6502 | stage));
        } catch (Exception e) {
            ISOException.throwIt((short) (0x6503 | stage));
        }
    }
}
