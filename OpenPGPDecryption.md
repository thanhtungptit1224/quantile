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
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Iterator;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * TCB example for decryption encrypted reconfiles.
 *
 * Encryption standard: OpenGPG Crypto library usage: BouncyCastle Log library
 * usage: Log4j
 *
 * More examples from Bouncy Castle:
 * https://github.com/bcgit/bc-java/tree/master/pg/src/main/java/org/bouncycastle/openpgp/examples
 *
 * @author tcbsupport
 * @version 0.8
 */
public class OpenPGPDecryption {

    private static final Logger log = Logger.getLogger(OpenPGPDecryption.class);

    public static void main(String[] args) {
        try {

            if (args == null || args.length < 4) {
                System.out.println("Usage: java -cp \"lib/*\" vn.tcb.recon.security.OpenPGPDecryption [Root-Folder] [Parnter-Private-Key-Path] [Partner-Passphrase] [TCB-Public-Key-Path]");
                return;
            }

            // Root folder (direct parent folder of reconcile folder)
            final String rootFolder = args[0];

            // Partner keys paths
            final String partnerKeyPath = args[1];
            final String partnerPassphrase = args[2];

            // TCB public key path
            final String tcbPublicKeyPath = args[3];

            // Working folders
            final String encryptFolder = rootFolder + "/encrypt";
            final String decryptFolder = rootFolder + "/decrypt";
            final String verifyFolder = rootFolder + "/verify";
            final String archiveFolder = rootFolder + "/archive";

            // Configure log file with date and time
            Calendar cal = Calendar.getInstance();
            final int year = cal.get(Calendar.YEAR);
            final int month = cal.get(Calendar.MONTH) + 1;
            final int day = cal.get(Calendar.DAY_OF_MONTH);
            final int hour = cal.get(Calendar.HOUR_OF_DAY);
            final int minute = cal.get(Calendar.MINUTE);
            final int second = cal.get(Calendar.SECOND);
            final String curdate = String.valueOf(year) + (month < 10 ? "-0" + month : "-" + month) + (day < 10 ? "-0" + day : "-" + day);
            final String curtime = String.valueOf(hour) + ":" + minute + ":" + second;
            configLog4j(rootFolder, curdate);

            // Start do decrypt
            log.info("++++++++++++++++++++++++++++++ Date: " + curdate + " and Time: " + curtime + " ++++++++++++++++++++++++++++");
            log.info("Looping through all files in " + encryptFolder + ", looking for pgp files to decrypt");
            log.info("---------------------------------------- Thread Start ---------------------------------------------");

            // Add Bouncy Castle Provider
            Security.addProvider(new BouncyCastleProvider());

            // Partner decrypt files (*.pgp) in encrypt folder with partner secret key
            boolean decryptSuccess = partnerDecryptReconfiles(encryptFolder, decryptFolder, partnerKeyPath, partnerPassphrase);
            if (!decryptSuccess) {
                log.info("----------------------------- Thread End (Decrypt Error) ------------------------------------");
                return;
            }

            // Partner verify (clean signed) reconfiles with TCB public key
            boolean verifySuccess = partnerVerifyReconfiles(decryptFolder, verifyFolder, tcbPublicKeyPath);
            if (!verifySuccess) {
                log.info("----------------------------- Thread End (Verify Error) ----------------------------------------");
                return;
            }

            // Do archive reconfiles
            archiveReconfiles(encryptFolder, archiveFolder, curdate);

            log.info("----------------------------------------- Thread End ----------------------------------------------");

        } catch (Exception e) {
            log.error("Error test TCB Crypto.", e);
        }
    }

    /**
     * Decrypt reconfiles with partner private key
     *
     * @param encryptFolder
     * @param decryptFolder
     * @param partnerKeyPath
     * @param partnerPassphrase
     * @return
     * @throws Exception
     */
    static boolean partnerDecryptReconfiles(String encryptFolder, String decryptFolder, String partnerKeyPath, String partnerPassphrase) throws Exception {

        // Load Partner key
        final char[] pass = partnerPassphrase.toCharArray();
        long startTime = System.currentTimeMillis();

        // Check out put folder
        final File outputFolder = new File(decryptFolder);
        if (!outputFolder.exists()) {
            outputFolder.mkdirs();
        }

        // List all encrypted reconfiles and do decrypt with partner private key
        final File[] encryptedFiles = new File(encryptFolder).listFiles();
        if (encryptedFiles == null) {
            log.error("Encrypt folder (store encrypted reconfiles) not found: " + encryptFolder);
            return false;
        }

        log.info("Start decrypt reconfiles in folder: " + encryptFolder);

        for (File encryptedFile : encryptedFiles) {

            // ignore none pgp files
            if (!encryptedFile.isFile() || !encryptedFile.getName().endsWith(".pgp")) {
                log.info("Ignore none .pgp file: " + encryptedFile.getAbsolutePath());
                continue;
            }

            // build decrypt file path
            final File decryptFile = new File(decryptFolder + "/" + encryptedFile.getName().replace(".pgp", ".sig"));

            // do decrypt file
            InputStream dataIn = new BufferedInputStream(new FileInputStream(encryptedFile));
            InputStream keyIn = new FileInputStream(partnerKeyPath);
            boolean success = decryptFile(dataIn, keyIn, pass, decryptFile);
            if (success) {
                log.info("Decrypted file: " + encryptedFile.getName() + " and saved to: " + decryptFile.getAbsolutePath() + " successfully.");
            } else {
                log.info("Decrypted file: " + encryptedFile.getName() + " and saved to: " + decryptFile.getAbsolutePath() + " ERROR!!!!!");
                return false;
            }

        }
        log.info("Partner decrypted reconfiles success. Total processing time: " + (System.currentTimeMillis() - startTime) + "ms.");

        return true;
    }

    /**
     * Partner verify clean signed folder with TCB public key
     *
     * @param verifyFolder
     * @param tcbPublicKeyPath
     * @return
     * @throws Exception
     */
    static boolean partnerVerifyReconfiles(String decryptFolder, String verifyFolder, String tcbPublicKeyPath) throws Exception {

        log.debug("Start partner verifying reconfiles..");
        long startTime = System.currentTimeMillis();

        // Check out put folder
        final File outputFolder = new File(verifyFolder);
        if (!outputFolder.exists()) {
            outputFolder.mkdirs();
        }

        // List all clean text signed reconfiles and do verify with TCB public key
        final File[] decryptedFiles = new File(decryptFolder).listFiles();
        for (File decryptedFile : decryptedFiles) {

            // ignore none pgp files
            if (!decryptedFile.isFile() || !decryptedFile.getName().endsWith(".sig")) {
                log.info("Ignore none .sig file: " + decryptedFile.getAbsolutePath());
                continue;
            }

            // build original file path
            final File originalFile = new File(verifyFolder + "/" + decryptedFile.getName().replace(".sig", ""));

            // do decrypt file
            InputStream dataIn = new FileInputStream(decryptedFile);
            InputStream keyIn = new FileInputStream(tcbPublicKeyPath);
            boolean success = verifyFile(dataIn, keyIn, originalFile);
            if (success) {
                log.info("Verified file: " + decryptedFile.getName() + " and saved to: " + originalFile.getAbsolutePath() + " successfully.");
            } else {
                log.error("Verified file: " + decryptedFile.getName() + " and saved to: " + originalFile.getAbsolutePath() + " ERROR!!!!!");
                // return
                return false;
            }

        }
        log.info("Partner verified reconfiles success. Total processing time: " + (System.currentTimeMillis() - startTime) + "ms.");

        return true;
    }

    /**
     * Archive reconfiles in encrypt folder by date
     */
    static void archiveReconfiles(String encryptFolder, String archiveFolder, String curdate) throws IOException {
        try {

            log.info("Start archive reconfiles..");

            final File[] encryptedFiles = new File(encryptFolder).listFiles();

            for (File encryptedFile : encryptedFiles) {

                // ignore none pgp files
                if (!encryptedFile.isFile() || !encryptedFile.getName().endsWith(".pgp")) {
                    log.info("Ignore none .pgp file: " + encryptedFile.getAbsolutePath());
                    continue;
                }

                // build archive file path
                final File archiveFile = new File(archiveFolder + "/" + curdate + "/" + encryptedFile.getName().replace(".pgp", ".pgp.bak"));
                if (!archiveFile.getParentFile().exists()) {
                    archiveFile.getParentFile().mkdirs();
                }

                // Rename file to archive file
                encryptedFile.renameTo(archiveFile);

                log.info("Archived file: " + encryptedFile.getName() + " to " + archiveFile.getAbsolutePath());
            }

            log.info("Archived reconfiles success.");
        } catch (Exception e) {
            log.error("Error archive reconfiles.", e);
        }
    }

    /**
     * Decrypt the passed in message stream
     */
    private static boolean decryptFile(InputStream dataIn, InputStream keyIn, char[] passwd, File decryptFile)
            throws IOException, NoSuchProviderException {

        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(dataIn));
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = it.next();

                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(decryptFile));

                Streams.pipeAll(unc, fOut);

                fOut.close();
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    // log.error("Message failed integrity check");
                    throw new PGPException("Message failed integrity check");
                } else {
                    // log.error("Message integrity check passed");
                }
            } else {
                log.warn("No message integrity check when decrypt file: " + decryptFile.getName());
            }

            return true;
        } catch (PGPException e) {
            log.error("Error decrypt file: " + e.getMessage(), e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }

        return false;
    }

    /*
	 * verify a clear text signed file
     */
    private static boolean verifyFile(InputStream dataIn, InputStream keyIn, File originalFile) throws Exception {

        ArmoredInputStream aIn = new ArmoredInputStream(dataIn);
        OutputStream out = new BufferedOutputStream(new FileOutputStream(originalFile));

        //
        // write out signed section using the local line separator.
        // note: trailing white space needs to be closed from the end of
        // each line RFC 4880 Section 7.1
        //
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, aIn);
        byte[] lineSep = getLineSeparator();

        if (lookAhead != -1 && aIn.isClearText()) {
            byte[] line = lineOut.toByteArray();
            out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
            out.write(lineSep);

            while (lookAhead != -1 && aIn.isClearText()) {
                lookAhead = readInputLine(lineOut, lookAhead, aIn);

                line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        } else {
            // a single line file
            if (lookAhead != -1) {
                byte[] line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        }

        out.close();

        PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
        PGPSignature sig = p3.get(0);

        PGPPublicKey publicKey = pgpRings.getPublicKey(sig.getKeyID());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

        //
        // read the input, making sure we ignore the last newline.
        //
        InputStream sigIn = new BufferedInputStream(new FileInputStream(originalFile));

        lookAhead = readInputLine(lineOut, sigIn);

        processLine(sig, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                sig.update((byte) '\r');
                sig.update((byte) '\n');

                processLine(sig, lineOut.toByteArray());
            } while (lookAhead != -1);
        }

        sigIn.close();

        if (sig.verify()) {
            // log.info("Signature verified.");
            return true;
        } else {
            // log.error("Signature verification failed.");
            return false;
        }
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to
     * keyID if it exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    /**
     * Config log4j, default to logs/decrypt_date.log
     */
    private static void configLog4j(String rootFolder, String curdate) {

        ConsoleAppender console = new ConsoleAppender(); // create appender
        // configure the appender
        String PATTERN = "%d %-5p [%c{1}] %m%n";
        console.setLayout(new PatternLayout(PATTERN));
        console.setThreshold(Level.DEBUG);
        console.activateOptions();
        // add appender to root Logger
        Logger.getRootLogger().addAppender(console);

        // set default log files at root folder
        final File logsFolder = new File(rootFolder + "/logs");
        if (!logsFolder.exists()) {
            logsFolder.mkdirs();
        }

        FileAppender fa = new FileAppender();
        fa.setName("FileLogger");
        fa.setFile(logsFolder + "/DECRYPT_" + curdate + ".log");
        fa.setLayout(new PatternLayout("%d %-5p [%c{1}] %m%n"));
        fa.setThreshold(Level.DEBUG);
        fa.setAppend(true);
        fa.activateOptions();

        // add appender to root
        Logger.getRootLogger().addAppender(fa);
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

    private static byte[] getLineSeparator() {
        String nl = Strings.lineSeparator();
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }

    private static void processLine(PGPSignature sig, byte[] line)
            throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

}

```
