```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package vn.tcb.recon.utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.util.Iterator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class TcbSecurity {
    private static String salt = "hywebpg5";
    private static String mode = "ECB";
    private static String padding = "NoPadding";

    public TcbSecurity() {
    }

    public static byte[] compressFile(File file, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), 'b', file);
        comData.close();
        return bOut.toByteArray();
    }

    public static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        return pgpSecKey == null ? null : pgpSecKey.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(pass));
    }

    public static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey((InputStream)keyIn);
        keyIn.close();
        return pubKey;
    }

    public static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpPub.getKeyRings();

        while(keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getPublicKeys();

            while(keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey((InputStream)keyIn);
        keyIn.close();
        return secKey;
    }

    public static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpSec.getKeyRings();

        while(keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getSecretKeys();

            while(keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    public static String Encrypt(String msg, String k, String type) throws Exception {
        SecretKeySpec skey = getKey(k, type);
        msg = padding(msg);
        byte[] plainBytes = msg.getBytes("UTF-8");
        String encMode = type + "/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(encMode);
        IvParameterSpec ivspec = new IvParameterSpec(salt.getBytes("UTF-8"));
        if ("CBC".equals(mode)) {
            cipher.init(1, skey, ivspec);
        } else {
            cipher.init(1, skey);
        }

        byte[] cipherText = cipher.doFinal(plainBytes);
        return byte2hex(cipherText);
    }

    public static String Decrypt(String msg, String k, String type) throws Exception {
        System.setProperty("file.encoding", "UTF-8");
        SecretKeySpec skey = getKey(k, type);
        byte[] inPut = hex2byte(msg);
        String decMode = type + "/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(decMode);
        IvParameterSpec ivspec = new IvParameterSpec(salt.getBytes("UTF-8"));
        if ("CBC".equals(mode)) {
            cipher.init(2, skey, ivspec);
        } else {
            cipher.init(2, skey);
        }

        byte[] output = cipher.doFinal(inPut);
        String tem = new String(removePadding(output), "UTF-8");
        return tem;
    }

    public static String DESMAC(String msg, String k, String type) throws Exception {
        System.setProperty("file.encoding", "UTF-8");
        SecretKeySpec skey = getKey(k, type);
        msg = sha1(msg);
        byte[] mgsByte = macPadding(msg);
        String encMode = type + "/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(encMode);
        IvParameterSpec ivspec = new IvParameterSpec(salt.getBytes("UTF-8"));
        if ("CBC".equals(mode)) {
            cipher.init(1, skey, ivspec);
        } else {
            cipher.init(1, skey);
        }

        byte[] cipherText = cipher.doFinal(mgsByte);
        return byte2hex(cipherText);
    }

    public static String sha1(String input) throws Exception {
        System.setProperty("file.encoding", "UTF-8");

        try {
            MessageDigest mDigest = MessageDigest.getInstance("SHA1");
            byte[] result = mDigest.digest(input.getBytes("UTF-8"));
            StringBuffer sb = new StringBuffer();

            for(int i = 0; i < result.length; ++i) {
                sb.append(Integer.toString((result[i] & 255) + 256, 16).substring(1));
            }

            return sb.toString();
        } catch (Exception var5) {
            throw new Exception("SHA-1: " + var5.toString());
        }
    }

    private static String byte2hex(byte[] b) {
        System.setProperty("file.encoding", "UTF-8");
        String hs = "";
        String stmp = "";

        for(int n = 0; n < b.length; ++n) {
            stmp = Integer.toHexString(b[n] & 255);
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }

            if (n < b.length - 1) {
                hs = hs + "";
            }
        }

        return hs.toUpperCase();
    }

    private static byte[] hex2byte(String hex) throws IllegalArgumentException {
        System.setProperty("file.encoding", "UTF-8");
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException();
        } else {
            char[] arr = hex.toCharArray();
            byte[] b = new byte[hex.length() / 2];
            int i = 0;
            int j = 0;

            for(int l = hex.length(); i < l; ++j) {
                String swap = "" + arr[i++] + arr[i];
                int byteint = Integer.parseInt(swap, 16) & 255;
                b[j] = (new Integer(byteint)).byteValue();
                ++i;
            }

            return b;
        }
    }

    private static String padding(String str) throws Exception {
        System.setProperty("file.encoding", "UTF-8");
        byte[] oldByteArray = str.getBytes("UTF-8");
        int numberToPad = 8 - oldByteArray.length % 8;
        byte[] newByteArray = new byte[oldByteArray.length + numberToPad];
        System.arraycopy(oldByteArray, 0, newByteArray, 0, oldByteArray.length);

        for(int i = oldByteArray.length; i < newByteArray.length; ++i) {
            newByteArray[i] = 0;
        }

        return new String(newByteArray);
    }

    public static byte[] hexStringToByteArray(String s) {
        System.setProperty("file.encoding", "UTF-8");
        int len = s.length();
        byte[] data = new byte[len / 2];

        for(int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }

        return data;
    }

    private static byte[] macPadding(String str) {
        System.setProperty("file.encoding", "UTF-8");
        byte[] oldByteArray = hexStringToByteArray(str);
        int numberToPad = 8 - oldByteArray.length % 8;
        byte[] newByteArray = new byte[oldByteArray.length + numberToPad];
        System.arraycopy(oldByteArray, 0, newByteArray, 0, oldByteArray.length);

        for(int i = oldByteArray.length; i < newByteArray.length; ++i) {
            newByteArray[i] = 0;
        }

        return newByteArray;
    }

    private static byte[] removePadding(byte[] oldByteArray) {
        System.setProperty("file.encoding", "UTF-8");
        int numberPaded = 0;

        for(int i = oldByteArray.length; i >= 0; --i) {
            if (oldByteArray[i - 1] != 0) {
                numberPaded = oldByteArray.length - i;
                break;
            }
        }

        byte[] newByteArray = new byte[oldByteArray.length - numberPaded];
        System.arraycopy(oldByteArray, 0, newByteArray, 0, newByteArray.length);
        return newByteArray;
    }

    private static SecretKeySpec getKey(String keys, String mode) {
        System.setProperty("file.encoding", "UTF-8");
        SecretKeySpec pass = new SecretKeySpec(keys.getBytes(), mode);
        return pass;
    }

    public static String ConvertToUTF8(String s) {
        String out = null;

        try {
            out = new String(s.getBytes("UTF-8"), "ISO-8859-1");
            return out;
        } catch (UnsupportedEncodingException var3) {
            return null;
        }
    }
}

```
