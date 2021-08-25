```
package vn.tcb.recon.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import vn.tcb.recon.bean.ReconPartner;
import vn.tcb.recon.utils.SysUtils;
import vn.tcb.recon.utils.TcbSecurity;
import vn.tcb.recon.xml.XMLConfigFile;
import vn.tcb.recon.xml.XMLmsg;

/**
 *
 * Sign then encrypt with OpenPGP using Bouncy Castle library.
 *
 */
public class OpenPGPEncryption {

    private static final Logger log = Logger.getLogger(OpenPGPEncryption.class);

    // TCB PGP secret key
    private static PGPSecretKey pgpSecKey;
    private static PGPPrivateKey pgpPrivKey;

    /*
	 * Initialize encryption class
     */
    public static boolean initialize() {

        // Add Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            String xmlConfigFile = XMLConfigFile.getValue("security");
            if(xmlConfigFile == null) throw new Exception("Can not read config security file");
            XMLmsg xmLmsg = XMLmsg.parseFile(xmlConfigFile);
            final String tcbKeyPath = xmLmsg.getValue("pgpKeyPath", "config/TCBKeys.gpg");
            final String passpharseEnc = xmLmsg.getAttribute("pgpKeyPath", "passphrase");

            // decrypt user name / password
            final String secKey = xmLmsg.getValue("desKey", "").trim();
            final String secType = xmLmsg.getValue("desType", "").trim();

            String passpharse = passpharseEnc;
            if (!secKey.isEmpty()) {
                passpharse = SysUtils.decrypt(passpharseEnc, secKey, secType);
            }

            // Load TCB key
            InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(tcbKeyPath));

            pgpSecKey = TcbSecurity.readSecretKey(keyIn);
            pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passpharse.toCharArray()));

            keyIn.close();
        } catch (Exception e) {
            log.error("Error load TCB PGP secret key.", e);
        }

        log.debug("Initialized Open PGP encryption..");

        return true;
    }

    /**
     * Close Open PGP encryption
     */
    public static boolean close() {
        return true;
    }

//    /**
//     * Clear sign file then encrypt file with Open PGP before save to partner
//     * FTP folder
//     *
//     * @param reconfile
//     * @param partner
//     * @return Signed file path
//     * @throws Exception
//     */
    public static String encryptSignFile(Logger reconLog, String reconfilePath, ReconPartner partner) throws Exception {

        // build reconcile file
        File reconFile = new File(reconfilePath);

        reconLog.debug(new StringBuffer("Start sign and encrypt file: ").append(reconfilePath));

        // build sign file
        File signFile = new File(reconfilePath + ".sig");

        // do sign reconciliation file
        boolean success = processClearsignReconfiles(reconLog, reconFile, signFile);
        if (!success) {
            return null;
        }

        // build encrypt file
        // final String filePath = partner.exportFolder + "/" + fileName;
        // File encryptFile = new File(partner.exportFolder + "/" + reconFile.getName() + ".pgp");
        File encryptFile = new File(reconfilePath + ".pgp");

        // do encrypt file
        success = processEncryptReconfiles(reconLog, signFile, encryptFile, partner.pgpPubKey);
        if (!success) {
            return null;
        }

        return encryptFile.getAbsolutePath();
    }

    /**
     * Encrypt file with partner public key and return .pgp file path
     */
    public static String encryptFile(Logger reconLog, String reconfilePath, ReconPartner partner) throws Exception {

        // build reconcile file
        File reconFile = new File(reconfilePath);

        reconLog.debug(new StringBuffer("Start encrypt file: ").append(reconfilePath));

        // build encrypt file
        File encryptFile = new File(reconfilePath + ".pgp");

        // do encrypt file
        boolean success = processEncryptReconfiles(reconLog, reconFile, encryptFile, partner.pgpPubKey);
        if (!success) {
            return null;
        }

        return encryptFile.getAbsolutePath();
    }

    /**
     * Sign file with TCB public key only and return .sig file path
     */
    public static String signFile(Logger reconLog, String reconfilePath, ReconPartner partner) throws Exception {

        // build reconcile file
        File reconFile = new File(reconfilePath);

        reconLog.debug(new StringBuffer("Start clear sign file: ").append(reconfilePath));

        // build sign file
        File signFile = new File(reconfilePath + ".sig");

        // do sign reconciliation file
        boolean success = processClearsignReconfiles(reconLog, reconFile, signFile);
        if (!success) {
            return null;
        }

        return signFile.getAbsolutePath();
    }

//    /**
//     * TCB signing and encrypting reconcile files with OpenPGP encryption
//     * standard.
//     *
//     * @param outboundFolder The folder on DMZ stored plain text reconcile
//     * files.
//     * @param tcbKeyPath TCB keys file path (contains private key)
//     * @param partnerPublicKeyPath Partner public key path
//     * @return True if test signing and encrypting success else return False
//     * @throws Exception Throws any exceptions
//     */
    static boolean processClearsignReconfiles(Logger reconLog, File reconfile, File signFile) throws Exception {

        reconLog.debug("Start signing and encrypting reconfiles with OpenPGP..");
        long startTime = System.currentTimeMillis();

        final int digest = PGPUtil.SHA256;

        // PGPSignature
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), digest).setProvider("BC"));
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);

        Iterator<String> it = pgpSecKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            spGen.setSignerUserID(false, it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        // *********************************************************************************//
        InputStream fIn = null;
        FileOutputStream signOut = null;
        BCPGOutputStream bOut = null;
        try {

            // open reconfile
            fIn = new BufferedInputStream(new FileInputStream(reconfile));

            // out put file to ENCRYPT_FOLDER/reconfile.sig
            signOut = new FileOutputStream(signFile);
            ArmoredOutputStream armoredOut = new ArmoredOutputStream(signOut);

            armoredOut.beginClearText(digest);

            //
            // note the last \n/\r/\r\n in the file is ignored
            //
            ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
            int lookAhead = readInputLine(lineOut, fIn);
            int writeLength = 0;

            processLine(armoredOut, sGen, lineOut.toByteArray());

            if (lookAhead != -1) {
                do {
                    lookAhead = readInputLine(lineOut, lookAhead, fIn);

                    sGen.update((byte) '\r');
                    sGen.update((byte) '\n');

                    writeLength = processLine(armoredOut, sGen, lineOut.toByteArray());

                    // fix last line error
                    if (lookAhead == -1 && writeLength > 0) {
                        // sGen.update((byte) '\r');
                        // sGen.update((byte) '\n');
                    }

                } while (lookAhead != -1);
            }

            fIn.close();
            fIn = null;

            armoredOut.endClearText();

            bOut = new BCPGOutputStream(armoredOut);

            sGen.generate().encode(bOut);

            // BCPG out close
            bOut.close();
            bOut = null;

            // close file out put stream
            signOut.close();
            signOut = null;

            // NOTE: close armoredOut only cause file not close correctly
            reconLog.info(new StringBuffer("TCB clear text sign success for file: ").append(reconfile.getName())
                    .append(". Total processing time: ").append(System.currentTimeMillis() - startTime).append("ms."));

            return true;
        } catch (Exception e) {
            reconLog.error(new StringBuffer("Error clearsign reconfile: ").append(reconfile.getAbsolutePath()), e);
        } finally {

            if (fIn != null) {
                // retry close file input stream
                try {
                    fIn.close();
                } catch (Exception e) {
                }
            }

            if (bOut != null) {
                // retry close BCBP output stream
                try {
                    bOut.close();
                } catch (Exception e) {
                }
            }

            if (signOut != null) {
                // retry close file output stream
                try {
                    signOut.close();
                } catch (Exception e) {
                }
            }
        }

        return false;
    }

//    /**
//     * TCB encrypt signed file with partner public key
//     *
//     * @param signingFolder
//     * @param partherPublicKeyPath
//     * @return
//     * @throws Exception
//     */
    static boolean processEncryptReconfiles(Logger reconLog, File signedFile, File encryptFile, PGPPublicKey pgpPubKey) throws Exception {

        reconLog.debug("Start encrypt reconfiles with partner public key..");
        long startTime = System.currentTimeMillis();
        boolean withIntegrityCheck = true;

        // Create PGP encrypted data generator (using AES-256)
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

        // Set partner public key
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPubKey).setProvider("BC"));

        OutputStream encryptFileOut = null;
        OutputStream cOut = null;
        try {

            // Load and compress signed file
            final byte[] compressedData = TcbSecurity.compressFile(signedFile, CompressionAlgorithmTags.ZIP);

            // Create output stream to write encrypted data to encrypt folder
            encryptFileOut = new BufferedOutputStream(new FileOutputStream(encryptFile));

            cOut = encGen.open(encryptFileOut, compressedData.length);
            cOut.write(compressedData);

            cOut.close();
            cOut = null;

            encryptFileOut.close();
            encryptFileOut = null;

            reconLog.info(new StringBuffer("TCB encrypted success for file: ").append(signedFile.getName())
                    .append(". Total processing time: ").append(System.currentTimeMillis() - startTime).append("ms."));

            return true;
        } catch (Exception e) {
            reconLog.error(new StringBuffer("Error encrypt file with partner public key: ").append(signedFile.getAbsolutePath()), e);
        } finally {

            if (cOut != null) {
                // retry close PGP out stream
                try {
                    cOut.close();
                } catch (Exception e) {
                }
            }

            if (encryptFileOut != null) {
                // retry close file output stream
                try {
                    encryptFileOut.close();
                } catch (Exception e) {
                }
            }
        }

        return false;
    }

    /**
     * **********************************************************************************************************************
     */
    /**
     * **************************************** HELPER METHODS          ********************************************
     */
    /**
     * **********************************************************************************************************************
     */
    /*
     * Read input line
     */
    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn) throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn) throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        } while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn) throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
            throws SignatureException, IOException {
        // note: trailing white space needs to be closed from the end of
        // each line for signature calculation RFC 4880 Section 7.1
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sGen.update(line, 0, length);
        }

        aOut.write(line, 0, line.length);

        return length;
    }
}
```
