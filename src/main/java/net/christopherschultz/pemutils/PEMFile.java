package net.christopherschultz.pemutils;
/**
 * Copyright 2021 Christopher Schultz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A PEM file reader.
 *
 * This class is capable of reading PEM files containing multiple entries
 * with optional comments, etc., separating entries identified by the
 * following headers:
 *
 * <pre>
-----BEGIN CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN EC PARAMETERS-----
-----BEGIN PUBLIC KEY-----
-----BEGIN X509 CRL-----
</pre>
 *
 * A special thanks to many unspecified askers and answerers on StackOverflow
 * for demonstrating how to parse some of the more esoteric types of DER
 * file. I'm sorry that I cannot properly give credit as this project took
 * quite a while and I wasn't keeping records as I went along. If you find
 * some code you wrote in here, let me know and I'll give you appropriate
 * credit.
 *
 * @author Christopher Schultz
 */
public class PEMFile {
    /**
     * Dumps the entries in a PEM file found on standard input.
     *
     * @param args Ignored
     */
    public static void main(String[] args) {
        if(0 < args.length && ("-h".equals(args[0]) || "--help".equals(args[0]))) {
            System.out.println("Usage: java PEMFile");
            System.out.println();
            System.out.println("Reads a series of PEM entries from standard input and prints them to standard output.");
            System.exit(0);
        }

        PEMFile pemFile = new PEMFile(System.in);

        PEMFile.Entry entry = null;
        do {
            try {
                entry = pemFile.getNext();

                if(null != entry) {
                    System.out.println("Got entry: " + entry);
                }
            } catch (Exception e) {
                System.err.println("Failed to read PEM entry:");
                e.printStackTrace();
                System.err.println("Continuing...");
            }
        } while (null != entry);
    }

    /**
     * Decodes the String argument as zero or more PEM entries.
     *
     * @param pem The String to decode.
     *
     * @return A Collection of Entry objects representing each item found in the PEM String.
     *
     * @throws IOException If there is a problem reading the PEM String.
     *
     * @throws GeneralSecurityException If there are any problems with the cryptographic information in the String.
     */
    public static Collection<Entry> decode(String pem) throws IOException, GeneralSecurityException {
        if(null == pem) {
            return null;
        }

        PEMFile pf = new PEMFile(new StringReader(pem));

        ArrayList<Entry> entries = new ArrayList<Entry>();
        Entry e;

        while(null != (e = pf.getNext())) {
            entries.add(e);
        }

        return entries;
    }

    /**
     * A PEM entry.
     */
    public static abstract class Entry {
        private final String header;
        private final String body;

        /**
         * Creates a new Entry.
         *
         * @param header The header of the entry (e.g. "CERTIFICATE").
         * @param body The body of the entry (e.g. the base64-encoded body
         *             of the certificate).
         */
        public Entry(String header, String body) {
            this.body = body;
            this.header = header;
        }

        /**
         * Returns the "header" of this Entry.
         *
         * @return The header of the entry.
         */
        public String getHeader() {
            return header;
        }

        /**
         * Returns the "body" of this entry.
         *
         * @return The body of the entry.
         */
        public String getBody() {
            return body;
        }

        /**
         * Returns the header of this Entry.
         *
         * @return The header of this Entry.
         */
        public String toString() {
            return header;
        }

        /**
         * Writes this entry to the specified Writer. The format is dependent
         * upon the specific type of Entry, but the default implementation will
         * dump out the header and body without any changes.
         *
         * @param w The Writer where this Entry should be written.
         *
         * @throws IOException If there is a problem writing to the Writer.
         * @throws GeneralSecurityException If there is a problem performing
         *         any cryptographic operation in order to write this Entry
         *         to the Writer.
         */
        public void write(Writer w) throws IOException, GeneralSecurityException {
            w.append("-----BEGIN ")
            .append(getHeader())
            .append("-----\n")
            .append(getBody())
            .append("\n-----END ")
            .append(getHeader())
            .append("\n");
        }

        private static final String PRIVATE_KEY="PRIVATE KEY";
        private static final String ENCRYPTED_PRIVATE_KEY="ENCRYPTED PRIVATE KEY";
        private static final String EC_PARAMETERS="EC PARAMETERS";
        private static final String EC_PRIVATE_KEY="EC PRIVATE KEY";
        private static final String RSA_PRIVATE_KEY="RSA PRIVATE KEY";
        private static final String PUBLIC_KEY="PUBLIC KEY";
        private static final String CERTIFICATE="CERTIFICATE";
        private static final String X509_CRL="X509 CRL";

        /**
         * Decodes a PEM entry given its header and body.
         *
         * @param header The header of the PEM entry without the hyphens or "BEGIN" e.g. ("CERTIFICATE").
         * @param body The body of the PEM entry, still base64 encoded.
         *
         * @return An appropriate Entry subclass which matches the header.
         *
         * @throws IOException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchPaddingException
         * @throws InvalidKeySpecException
         * @throws InvalidKeyException
         * @throws InvalidAlgorithmParameterException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         * @throws CertificateException
         */
        public static Entry decode(String header, String body, PasswordProvider passwordProvider)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CertificateException, CRLException
        {
            // TODO: DSA? Tests say it's covered. Where is BEGIN DSA PRIVATE KEY???
            if(PRIVATE_KEY.equals(header) || ENCRYPTED_PRIVATE_KEY.equals(header)) {
                // PKCS8, can be any type of Private Key

                return decodePKCS8PrivateKey(header, body, passwordProvider);
            } else if(CERTIFICATE.equals(header)) {
                return decodeCertificate(header, body);
            } else if(RSA_PRIVATE_KEY.equals(header)) {
                // RFC 3447 = BEGIN RSA PRIVATE KEY / pkcs1

                return decodePKCS1PrivateKey(header, body, passwordProvider);
            } else if(EC_PRIVATE_KEY.equals(header)) {
                // RFC 5915 = BEGIN EC PRIVATE KEY

                return decodeECPrivateKey(header, body);
            } else if(PUBLIC_KEY.equals(header)) {
                return decodePublicKey(header, body);
            } else if(EC_PARAMETERS.equals(header)) {
                return decodeECParameters(header, body);

            } else if(X509_CRL.equals(header)) {
                return decodeX509CRL(header, body);
            } else {
                return new UnknownEntry(header, body);
            }
        }

        /**
         * A generic, fall-back Entry indicating that we didn't know how to
         * decode a particular entry.
         */
        public static class UnknownEntry extends Entry {
            public UnknownEntry(String header, String body) {
                super(header, body);
            }

            public String toString() {
                return "Unknown: " + getHeader();
            }
        }

        /**
         * Decodes a PKCS1 (RSA) Private Key.
         */
        private static Entry decodePKCS1PrivateKey(String header, String body, PasswordProvider passwordProvider)
            throws IOException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            HashMap<String,String> params;
            String algorithm = "RSA"; // By definition
            PrivateKey key;

            // There might be some "parameters" at the top of this structure in
            // the form:
            // Parameter: value\n
            // Parameter: value

            // Let's see if we can detect them.
            int pos = body.indexOf(':');
            if(pos > 0) {
                params = new HashMap<String,String>();
                // We have found some parameters. Let's parse them.
                int skipLineCount = 0; // Remember to skip this stuff later
                BufferedReader in = null;
                try {
                    in = new BufferedReader(new StringReader(body));

                    String line;
                    while(null != (line = in.readLine())) {
                        // System.out.println("Got line: " + line);
                        if(0 == line.trim().length()) {
                            // Ignore blank lines
                            ++skipLineCount;
                        } else {
                            pos = line.indexOf(':');
                            if(pos > 0) {
                                params.put(line.substring(0, pos).trim(), line.substring(pos + 1).trim());
                                ++skipLineCount;
                            } else {
                                // Done with parameters
                                break;
                            }
                        }
                    }
                } finally {
                    if(null != in) try {
                        in.close();
                    } catch (IOException ioe) {
                        ioe.printStackTrace();
                    }
                }

                if(0 != skipLineCount) {
                    pos = -1;
                    int last = 0;
                    while(skipLineCount > 0) {
                        last = pos;
                        pos = body.indexOf('\n', pos + 1);
                        // System.out.println("Found newline at " + pos);
                        if(pos < 0) {
                            pos = last; // Back-up if necessary
                        }
                        --skipLineCount;
                    }

                    //System.out.println("Skipping to body pos=" + pos);
                    body = body.substring(pos);
                }
            } else {
                params = null;
            }

            // System.out.println("Params=" + params);
            // https://tools.ietf.org/html/rfc3447#appendix-A.1.2
            /*
          RSAPrivateKey ::= SEQUENCE {
              version           Version,
              modulus           INTEGER,  -- n
              publicExponent    INTEGER,  -- e
              privateExponent   INTEGER,  -- d
              prime1            INTEGER,  -- p
              prime2            INTEGER,  -- q
              exponent1         INTEGER,  -- d mod (p-1)
              exponent2         INTEGER,  -- d mod (q-1)
              coefficient       INTEGER,  -- (inverse of q) mod p
              otherPrimeInfos   OtherPrimeInfos OPTIONAL
          }
             */
            byte[] keydata = Base64.getMimeDecoder().decode(body);

            if(null != params && "4,ENCRYPTED".equals(params.get("Proc-Type"))) {
                if(null == passwordProvider) {
                    return new EncryptedPrivateKeyEntry(header, body);
                }

                String encryptionDetails = params.get("DEK-Info");

                pos = encryptionDetails.indexOf(",");
                if(pos < 0) {
                    throw new IllegalArgumentException("Encryption details (DEK-Info) do not include initialization vector");
                }

                String encryptionAlgorithm = encryptionDetails.substring(0, pos); // e.g. DES-EDE3-CBC
                String keyAlgorithm;
                int keyLength;
                if("DES-EDE3-CBC".equals(encryptionAlgorithm)) {
                    encryptionAlgorithm = "DESede/CBC/PKCS5Padding";
                    keyLength = 24;
                    keyAlgorithm = "DESede";
                } else if("DES-CBC".equals(encryptionAlgorithm)) {
                    encryptionAlgorithm = "DES/CBC/PKCS5Padding";
                    keyLength = 8;
                    keyAlgorithm = "DES";
                } else if("AES-256-CBC".equals(encryptionAlgorithm)) {
                    encryptionAlgorithm = "AES/CBC/PKCS5Padding";
                    keyLength = 32;
                    keyAlgorithm = "AES";
                } else {
                    throw new IllegalArgumentException("Unrecognized key encryption algorithm: " + encryptionAlgorithm);
                }
                // Unwrap the encryption
                Cipher c = Cipher.getInstance(encryptionAlgorithm);

                // NOTE: OpenSSL uses its own key-derivation function
                // Ref: https://stackoverflow.com/questions/35276820/decrypting-an-openssl-pem-encoded-rsa-private-key-with-java

                // Initialization Vector comes from the header
                byte[] iv = ASN1Stream.fromHexString(encryptionDetails.substring(pos+1));

                String password;
                boolean decrypted = false;
                do {
                    password = passwordProvider.getPassword();

                    if(null == password) {
                        break;
                    }

                    try {
                        c.init(Cipher.DECRYPT_MODE,
                                getPBKDF1SecretKey(keyAlgorithm, keyLength, password.getBytes(StandardCharsets.UTF_8), iv),
                                new IvParameterSpec(iv));

                        // Unwrap
                        keydata = c.doFinal(keydata);

                        decrypted = true;
                    } catch (BadPaddingException bpe) {
                        // Incorrect password

                        // Do nothing, try again
                    } catch (IllegalBlockSizeException ibse) {
                        // Incorrect password

                        // Do nothing, try again
                    }
                } while (!decrypted);

                if(!decrypted) {
                    return new EncryptedPrivateKeyEntry(header, body);
                }
            } else {
                // params do not indicate encryption
            }

            ASN1Stream a1s = new ASN1Stream(keydata);

            try {
                if(ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                   && -1 != a1s.nextLength()
                   && ASN1Stream.Tag.INTEGER.equals(a1s.nextTag())) // Version
                {
                    int version = a1s.getInt(a1s.nextLength()).intValue();
                    if(0 != version) {
                        throw new IllegalArgumentException("Java does not support multi-prime RSA keys");
                    }

                    BigInteger m = a1s.getInt();
                    BigInteger e = a1s.getInt();
                    BigInteger d = a1s.getInt();
                    BigInteger p = a1s.getInt();
                    BigInteger q = a1s.getInt();
                    BigInteger e1 = a1s.getInt();
                    BigInteger e2 = a1s.getInt();
                    BigInteger c = a1s.getInt();

                    //RSAPrivateKeySpec ks = new RSAPrivateKeySpec(m, d);
                    RSAPrivateKeySpec ks = new RSAPrivateCrtKeySpec(m, e, d, p, q, e1, e2, c);

                    key = KeyFactory.getInstance(algorithm).generatePrivate(ks);
                } else {
                    throw new IllegalArgumentException("Confused");
                }
            } catch (IllegalArgumentException iae) {
                iae.printStackTrace();

                System.err.println("Confused, dumping ASN.1 structure:");

                ASN1Stream.dump(keydata);

                throw iae;
            }

            return new PrivateKeyEntry(header, body, algorithm, key);
        }

        /**
         * Generates a SecretKey for use with OpenSSL-encrypted entries.
         *
         * @param pw The password for the key.
         * @param iv The initialization vector for the key.
         *
         * @return A SecretKey that can be used to decrypt some other data.
         *
         * @throws NoSuchAlgorithmException If the JVM doesn't support DESede.
         */
        private static SecretKey getPBKDF1SecretKey(String keyAlgorithm, int keyLength, byte[] pw, byte[] iv)
            throws NoSuchAlgorithmException
        {
            // https://datatracker.ietf.org/doc/html/rfc2898#section-6.1.2
            //
            // Notes:
            // The salt is always 8 bytes
            byte[] key = new byte[keyLength];

            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(pw);
            md5.update(iv);
            byte[] d0 = md5.digest();
            System.arraycopy(d0, 0, key, 0, Math.min(16, keyLength));
            if(keyLength > 16) {
                md5.update(d0);
                md5.update(pw);
                md5.update(iv);
                byte[] d1 = md5.digest();
                System.arraycopy(d1, 0, key, 16, Math.min(keyLength - 16, 16));
            }

            return new SecretKeySpec(key, keyAlgorithm);
        }

        /**
         * Decodes a PKCS8 Entry.
         */
        private static Entry decodePKCS8PrivateKey(String header, String body, PasswordProvider passwordProvider)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            String algorithm;
            PrivateKey key;

            byte[] keydata;

            // KeyFactory needs to know what kind of key we have.
            // We therefore have to read the ASN.1 structure to determine
            // which type it is.

            // Decrypt if necessary.
            if(header.toUpperCase().startsWith("ENCRYPTED ")) {
                if(null == passwordProvider) {
                    return new EncryptedPrivateKeyEntry(header, body);
                }

                keydata = Base64.getMimeDecoder().decode(body);

                // Unwrap encrypted data
                EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
                try {
                    encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(keydata);

                    String algo = encryptedPrivateKeyInfo.getAlgName();

                    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);

                    String password;
                    boolean decrypted = false;
//                    int attempts = 0;
                    do {
                        password = passwordProvider.getPassword();

                        if(null == password) {
                            break;
                        }
                        try {
//                            System.out.println("Trying password " + password + " attempt " + (++attempts));
                            SecretKey secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(password.toCharArray()));

                            Cipher cipher = Cipher.getInstance(algo);
                            cipher.init(Cipher.DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());

                            byte[] decryptedKey = cipher.doFinal(encryptedPrivateKeyInfo.getEncryptedData());

                            keydata = decryptedKey;
                            decrypted = true;
                            break;
                        } catch (BadPaddingException bpe) {
                            // Decryption failed

                            // Do nothing; request another password
                            // System.out.println("Failed decryption; trying another password after " + password);
                        }
                    } while(!decrypted);

                    if(!decrypted) {
                        return new EncryptedPrivateKeyEntry(header, body);
                    }
                } catch (IOException ioe) {

                    // This may be type of key not supported by the JVM as of Java 15.
                    //
                    // Note: https://bugs.openjdk.java.net/browse/JDK-8231581

                    ASN1Stream a1s = new ASN1Stream(keydata);

                    // https://datatracker.ietf.org/doc/html/rfc2898#appendix-A.2
                    // Supported ASN.1 structure:
                    //
                    // SEQUENCE(2 elem)
                    //   SEQUENCE(2 elem)
                    //     OBJECT IDENTIFIER 1.2.840.113549.1.5.13 <--- OID of key-derivation structure (??) (e.g. Password-Based Encryption Scheme 2 (PBES2) in this case)
                    //     SEQUENCE(2 elem)
                    //       SEQUENCE(2 elem)
                    //         OBJECT IDENTIFIER 1.2.840.113549.1.5.12 <-- OID of key-derivation algorithm (e.g. Password-Based Key Derivation Function 2 (PBKDF2))
                    //         SEQUENCE(2 elem)
                    //           OCTET STRING(8 byte) F7F1520689D469C6 <--- salt
                    //           INTEGER 2048  <--- iteration count
                    //       SEQUENCE(2 elem)
                    //         OBJECT IDENTIFIER 1.2.840.113549.3.7  <--- OID of key-derivation symmetric cipher suite (e.g. Triple Data Encryption Standard (DES) algorithm coupled with a cipher-block chaining mode of operation (szOID_RSA_DES_EDE3_CBC) in this case)
                    //         OCTET STRING(8 byte) 9D1A44BCC1884EA7 <--- initialization vector
                    //   OCTET STRING(1224 byte) BC25A49838AB9D30D345469CCBED030866016DCC... <-- encrypted key info
                    //

                    String kdfOID;
                    byte[] salt;
                    int iterations;
                    String cipherOID;
                    byte[] iv;
                    byte[] encryptedKey;

                    if(ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                       && -1 != a1s.nextLength()
                       && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                       && -1 != a1s.nextLength()
                       && ASN1Stream.Tag.OID.equals(a1s.nextTag())
                       && "1.2.840.113549.1.5.13".equals(a1s.getOID(a1s.nextLength())) // PBES2
                       && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                       && -1 != a1s.nextLength()
                       && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                       && -1 != a1s.nextLength()
                       && ASN1Stream.Tag.OID.equals(a1s.nextTag())
                       && (null != (kdfOID = a1s.getOID(a1s.nextLength()))) // e.g. PBKDF2withHmacSHA1
                       && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                       && -1 != a1s.nextLength()
                       && ASN1Stream.Tag.OCTET_STRING.equals(a1s.nextTag())
                       && (null != (salt = a1s.getBytes(a1s.nextLength())))
                       && ASN1Stream.Tag.INTEGER.equals(a1s.nextTag())
                       && (-1 != (iterations = a1s.getInt(a1s.nextLength()).intValue()))
                       && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                       && -1 != a1s.nextLength()
                       && ASN1Stream.Tag.OID.equals(a1s.nextTag()) // e.g. DESede
                       && (null != (cipherOID = a1s.getOID(a1s.nextLength())))
                       && ASN1Stream.Tag.OCTET_STRING.equals(a1s.nextTag())
                       && (null != (iv = a1s.getBytes(a1s.nextLength())))
                       && ASN1Stream.Tag.OCTET_STRING.equals(a1s.nextTag())
                       && (null != (encryptedKey = a1s.getBytes(a1s.nextLength())))
                       )
                    {
                        String kdfAlgorithm = ALGORITHM_OIDS.get(kdfOID);
                        if(null == kdfAlgorithm) {
                            throw new UnsupportedOperationException("Unsupported key-derivation algorithm " + kdfOID);
                        }

                        String encryptionAlgorithm = ALGORITHM_OIDS.get(cipherOID);
                        if(null == encryptionAlgorithm) {
                            throw new UnsupportedOperationException("Unsupported encryption algorithm " + cipherOID);
                        }

                        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(kdfAlgorithm);

                        // Can we do this?
//                        encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(kdfAlgorithm, encryptedKey);

                        String password;
                        boolean decrypted = false;
//                        int attempts = 0;
                        do {
                            password = passwordProvider.getPassword();

                            if(null == password) {
                                break;
                            }

                            try {
//                                System.out.println("Trying password " + password);
                                PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, 24 * 8 /* Why is this fixed? */);

                                SecretKey secretKeyPbkdf = secretKeyFactory.generateSecret(pbeKeySpec);

                                String baseEncryptionAlgorithm;
                                int pos = encryptionAlgorithm.indexOf('/');
                                if(pos > 0) {
                                    // May need to convert "DESede/CBC/Padding" into "DESede"
                                    baseEncryptionAlgorithm = encryptionAlgorithm.substring(0, pos);
                                } else {
                                    baseEncryptionAlgorithm = encryptionAlgorithm;
                                }
                                SecretKey secretKey = new SecretKeySpec(secretKeyPbkdf.getEncoded(), baseEncryptionAlgorithm);

                                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

                                Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
                                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

                                byte[] decryptedKey = cipher.doFinal(encryptedKey);

                                keydata = decryptedKey;

                                decrypted = true;
                            } catch (BadPaddingException bpe) {
                                // Decryption failed

                                // Do nothing; request another password
                            }
                        } while(!decrypted);

                        if(!decrypted) {
                            return new EncryptedPrivateKeyEntry(header, body);
                        }
                    } else {
                        ASN1Stream.dump(keydata);

                        throw new IllegalArgumentException("Not sure how to parse this");
                    }
                }
            } else {
                // keydata is not encrypted
                keydata = Base64.getMimeDecoder().decode(body);
            }


            // PrivateKeyInfo ::= SEQUENCE {
            //    version Version,
            //    privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
            //    privateKey PrivateKey,
            //    attributes [0] Attributes OPTIONAL }
            //
            // Version ::= INTEGER {v1(0)} (v1,...)
            //
            // PrivateKey ::= OCTET STRING
            //
            // Attributes ::= SET OF Attribute

            // In English:
            // Expecting ASN.1 structure for non-encrypted key
            // SEQUENCE
            //   INTEGER <-- version
            //   SEQUENCE
            //     OID <-- OID of key algorithm
            // ... more stuff we don't actually care about
            //
            // SEQUENCE (len=46)
            //   INTEGER 0x0 (0 decimal)
            //   SEQUENCE (len=5)
            //     OID 1.3.101.110
            //     OCTET_STRING [bytes]


            ASN1Stream a1s = new ASN1Stream(keydata);

            if(ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                    && -1 != a1s.nextLength()
                    && ASN1Stream.Tag.INTEGER.equals(a1s.nextTag())
                    && (0 == a1s.getInt(a1s.nextLength()).intValue())
                    && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
                    && -1 != a1s.nextLength()
                    && ASN1Stream.Tag.OID.equals(a1s.nextTag()))
            {
                String oid = a1s.getOID(a1s.nextLength());

                algorithm = ALGORITHM_OIDS.get(oid);

                if(null == algorithm) {
                    System.out.println("ASN1 dump: " + Base64.getMimeEncoder().encodeToString(keydata));
                    throw new IllegalArgumentException("Unrecognized algorithm OID: " + oid);
                }

                KeyFactory kf = KeyFactory.getInstance(algorithm);

                ASN1Stream.Tag tag = a1s.nextTag();
                long len=0;

                if(ASN1Stream.Tag.NULL.equals(tag)) {
                    // This NULL appears to be optional. Skip it if we find one.
                    a1s.nextLength(); // ignore, will be 00
                    tag = a1s.nextTag();
                }

                // NOTE: Java doesn't seem to like X25519 keys as generated
                // by OpenSSL. You get an error that the key isn't 32-bits.
                // This is because the keys are double-wrapped in an
                // OCTET STRING, which is a little odd but correct.
                //
                // If we see 0x04 0x20 at the beginning of the key,
                // we'll "unwrap" it by extracting the 32-bit key
                // from the wrapper OCTET STRING.
                //
                // The same is true for X448 keys, where the length should be
                // 56 but it's 58 instead
                //
                if(ASN1Stream.Tag.OCTET_STRING.equals(tag)
                        && 34 == (len = a1s.nextLength())
                        && 34 == a1s.skip(len)) {
                    // Move the key
                    System.arraycopy(keydata, keydata.length - 32, keydata, keydata.length - 34, 32);
                    // Change the length
                    keydata[keydata.length - 35] = 32;
                } else if(ASN1Stream.Tag.OCTET_STRING.equals(tag)
                        && 58 == len
                        && 58 == a1s.skip(len)) {
                    // Move the key
                    System.arraycopy(keydata, keydata.length - 56, keydata, keydata.length - 58, 56);
                    // Change the length
                    keydata[keydata.length - 59] = 56;
                }
                KeySpec keySpec = new PKCS8EncodedKeySpec(keydata);

                key = kf.generatePrivate(keySpec);
            } else {
                System.err.println("Confused, dumping ASN.1 structure:");

                ASN1Stream.dump(keydata);

                return null;
            }

            return new PrivateKeyEntry(header, body, algorithm, key);
        }

        private static ECParameterSpec getECParameters(String oid)
            throws NoSuchAlgorithmException
        {
            NamedCurve curve = NamedCurve.forOID(oid);

            if(null == curve) {
                throw new NoSuchAlgorithmException("Unknown algorithm OID: " + oid);
            }

            return new ECParameterSpec(curve, new ECPoint(curve.getX(), curve.getY()), curve.getN(), curve.getH());
        }

        private static ECParametersEntry decodeECParameters(String header, String body)
            throws IOException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            byte[] info = Base64.getMimeDecoder().decode(body);

//            System.out.println("EC Parameters:");
//            ASN1Stream.dump(info);

            ASN1Stream a1s = new ASN1Stream(info);

            ASN1Stream.Tag tag;

            if(ASN1Stream.Tag.OID.equals(tag = a1s.nextTag())) {
                long len = a1s.nextLength();
                String oid = a1s.getOID(len);

                return new ECParametersEntry(header, body, getECParameters(oid));
            } else {
                throw new IllegalArgumentException("Expected OID, got " + tag);
            }
        }

        private static PrivateKeyEntry decodeECPrivateKey(String header, String body)
            throws IOException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
            String algorithm = "EC"; // By definition
            PrivateKey key;

            byte[] keydata = Base64.getMimeDecoder().decode(body);

            ASN1Stream a1s = new ASN1Stream(keydata);

            //
            // RFC 5915 - https://datatracker.ietf.org/doc/html/rfc5915#section-3

            // Expecting ASN.1 structure
            // SEQUENCE
            //   INTEGER (value=1)
            //   OCTET STRING (key data)
            //   CONTEXT_0
            //
            //   ECParameters (named curve, optional)
            //   BIT_STRING (optional)

            // SEQUENCE(4 elem)
            //   INTEGER (value=1)
            //   OCTET STRING(32 byte)  <-- private key bytes
            //   CONTEXT_0 [0](1)
            //     OBJECT IDENTIFIER    <-- curve OID e.g. 1.2.840.10045.3.1.7 (optional)
            //   CONTEXT_1
            //     BIT STRING(520 bit)  <-- public key (optional)

            ASN1Stream.Tag tag;
            if(ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
               && -1 != a1s.nextLength()
               && ASN1Stream.Tag.INTEGER.equals(tag = a1s.nextTag())
               && (0 == a1s.getInt(a1s.nextLength()).intValue())
               && ASN1Stream.Tag.OCTET_STRING.equals(tag = a1s.nextTag()))
            {
                byte[] keybytes = a1s.getBytes(a1s.nextLength());

                ECParameterSpec params;

                tag = a1s.nextTag();

                long len;

                if(ASN1Stream.Tag.CONTEXT_0 == tag
                   && -1 != a1s.nextLength()
                   && ASN1Stream.Tag.OID == (tag = a1s.nextTag())
                   && -1 != (len = a1s.nextLength())) {

                    String oid = a1s.getOID(len);

                    NamedCurve curve = NamedCurve.forOID(oid);

                    if(null == curve) {
                        throw new NoSuchAlgorithmException("Unknown algorithm OID: " + oid);
                    }

                    params = new ECParameterSpec(curve, new ECPoint(curve.getX(), curve.getY()), curve.getN(), curve.getH());
                } else {
                    System.err.println("Expected CONTEXT_0 and OID");

                    ASN1Stream.dump(keydata);

                    throw new IllegalStateException("Unexpected ASN.1 structure");
                }

                KeyFactory kf = KeyFactory.getInstance(algorithm);

                key = kf.generatePrivate(new ECPrivateKeySpec(new BigInteger(keybytes), params));
            }
            else {
                System.err.println("Confused, dumping ASN.1 structure:");

                ASN1Stream.dump(keydata);

                throw new IllegalStateException("Unexpected ASN.1 structure");
            }

            return new PrivateKeyEntry(header, body, algorithm, key);
        }
    }

    /**
     * An Entry subclass for Certificates (most likely X.509).
     */
    public static class CertificateEntry extends Entry {
        private final Certificate certificate;

        public CertificateEntry(String header, String body, Certificate certificate) {
            super(header, body);

            this.certificate = certificate;
        }

        public Certificate getCertificate() {
            return certificate;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();

            sb.append("CERTIFICATE: type=")
            .append(certificate.getType())
            ;

            if(certificate instanceof X509Certificate) {
                X509Certificate xc = (X509Certificate)certificate;
                sb.append(", subject=").append(xc.getSubjectDN());
            }
            return sb.toString();
        }

        /**
         * Writes the certificate as a PKCS#8 PEM-encoded DER file.
         *
         * @param w The Writer where the PEM entry should be written.
         */
        @Override
        public void write(Writer w) throws IOException, GeneralSecurityException {
            w.append("-----BEGIN CERTIFICATE-----\n")
            .append(java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(getCertificate().getEncoded()))
            .append("\n-----END CERTIFICATE-----\n")
            ;
        }
    }

    private static CertificateEntry decodeCertificate(String header, String body)
        throws IOException, CertificateException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return new CertificateEntry(header, body, cf.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(body))));
    }

    /**
     * An Entry subclass for Certificates (most likely X.509).
     */
    public static class X509CRLEntry extends Entry {
        private final X509CRL crl;

        public X509CRLEntry(String header, String body, X509CRL crl) {
            super(header, body);

            this.crl = crl;
        }

        public X509CRL getCRL() {
            return crl;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();

            sb.append("CRL: type=")
            .append(crl.getType())
            .append(", issuer=").append(crl.getIssuerDN())
            ;

            return sb.toString();
        }

        /**
         * Writes the certificate as a PKCS#8 PEM-encoded DER file.
         *
         * @param w The Writer where the PEM entry should be written.
         */
        @Override
        public void write(Writer w) throws IOException, GeneralSecurityException {
            w.append("-----BEGIN X509 CRL-----\n")
            .append(java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(crl.getEncoded()))
            .append("\n-----END X509 CRL-----\n")
            ;
        }
    }

    private static X509CRLEntry decodeX509CRL(String header, String body)
        throws IOException, CertificateException, CRLException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return new X509CRLEntry(header, body, (X509CRL)cf.generateCRL(new ByteArrayInputStream(Base64.getMimeDecoder().decode(body))));
    }

    public static final String RSA_OID = "1.2.840.113549.1.1.1";
    public static final String DSA_OID = "1.2.840.10040.4.1";
    public static final String EC_OID = "1.2.840.10045.2.1";
    // Diffie-Hellman
    public static final String DH_OID = "1.2.840.113549.1.3.1";
    // Rivest, Shamir, Adleman (RSA) Signature Scheme with Appendix - Probabilistic Signature Scheme (RSASSA-PSS)
    public static final String RSASSA_PSS_OID = "1.2.840.113549.1.1.10";
    public static final String PBKDF2withHmacSHA1_OID = "1.2.840.113549.1.5.12";
    public static final String DESede_OID = "1.2.840.113549.3.7";
    public static final String X25519_OID = "1.3.101.110";
    public static final String X448_OID = "1.3.101.111";

    private static final Map<String,String> ALGORITHM_OIDS;
    static {
        HashMap<String,String> map = new HashMap<String,String>();

        // Public Key algorithms
        map.put(DSA_OID, "DSA");
        map.put(RSA_OID, "RSA");
        map.put(EC_OID, "EC");
        map.put(DH_OID, "DH");
        map.put(RSASSA_PSS_OID, "RSASSA-PSS");
        map.put(X25519_OID, "X25519");
        map.put(X448_OID, "X448");

        // Key-derivation algorithms
        map.put(PBKDF2withHmacSHA1_OID, "PBKDF2withHmacSHA1");

        // Symmetric cipher algorithms
        map.put(DESede_OID, "DESede/CBC/PKCS5Padding");

        ALGORITHM_OIDS = Collections.unmodifiableMap(map);
    }

    /**
     * An Entry subclass for encrypted asymmetric private keys.
     */
    public static class EncryptedPrivateKeyEntry extends Entry {
        public EncryptedPrivateKeyEntry(String header, String body) {
            super(header, body);
        }
    }

    /**
     * An Entry subclass for asymmetric private keys.
     */
    public static class PrivateKeyEntry extends Entry {
        private String algorithm;
        private PrivateKey key;

        public PrivateKeyEntry(String header, String body, String algorithm, PrivateKey key)
        {
            super(header, body);

            this.algorithm = algorithm;
            this.key = key;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public PrivateKey getPrivateKey() {
            return key;
        }

        public String toString() {
            PrivateKey pk = getPrivateKey();

            if(pk instanceof ECPrivateKey) {
                EllipticCurve curve = ((ECPrivateKey)key).getParams().getCurve();

                EllipticCurve better = NamedCurve.forCurve(curve);

                if(null != better) {
                    curve = better;
                } else {
                    System.out.println(getBody());
                    /*
                    System.out.println("Couldn't find matching curve for " + curve);
                    System.out.println("A: " + curve.getA().toString(16));
                    System.out.println("B: " + curve.getB().toString(16));
                    if(curve.getField() instanceof ECFieldFp) {
                        ECFieldFp theirField = (ECFieldFp)curve.getField();
                        System.out.println("P=" + theirField.getP().toString(16));
                    } else if(curve.getField() instanceof ECFieldF2m) {
                        ECFieldF2m theirField = (ECFieldF2m)curve.getField();
                        System.out.println("M=" + theirField.getM());
                        System.out.println("ks=" + Arrays.toString(theirField.getMidTermsOfReductionPolynomial()));
                    }
                    /*

                    System.out.println("I think it's this curve: ");
                    EllipticCurve mine = NamedCurve.forOID("1.2.840.10045.3.0.11");
                    System.out.println("equals? " + mine.equals(curve));

                    System.out.println("A: " + mine.getA().toString(16));
                    System.out.println("B: " + mine.getB().toString(16));
                    if(mine.getField() instanceof ECFieldFp) {
                        ECFieldFp theirField = (ECFieldFp)mine.getField();
                        System.out.println("P=" + theirField.getP().toString(16));
                    } else if(mine.getField() instanceof ECFieldF2m) {
                        ECFieldF2m theirField = (ECFieldF2m)mine.getField();
                        System.out.println("M=" + theirField.getM());
                        System.out.println("ks=" + Arrays.toString(theirField.getMidTermsOfReductionPolynomial()));
                    }
/*                    */
                    //System.exit(1);
                }
                return getHeader() + ", " + roundBitsToByteBits(((ECPrivateKey)pk).getS().bitLength()) + " bits, curve=" + curve;
//                return getHeader() + ", " + roundBitsToByteBits(((ECPrivateKey)pk).getS().bitLength()) + " bits";
            } else if(pk instanceof RSAPrivateKey) {
                return getHeader() + ", " + algorithm + " " + (((RSAPrivateKey)pk).getModulus().bitLength() + " bits");
            } else if(pk instanceof DSAPrivateKey) {
                return getHeader() + ", " + algorithm + " " + (((DSAPrivateKey)pk).getParams().getP().bitLength() + " bits");
            } else if(pk instanceof DHPrivateKey) {
                return getHeader() + ", " + algorithm + " " + ((DHPrivateKey)pk).getParams().getP().bitLength() + " bits";
            } else {
                return getHeader() + ", " + algorithm + " key=" + key;
            }
        }

        /**
         * Writes the private key as a PKCS#8 PEM-encoded DER file.
         *
         * @param w The Writer where the PEM entry should be written.
         */
        @Override
        public void write(Writer w) throws IOException {
            w.append("-----BEGIN PRIVATE KEY-----\n")
            .append(java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(getPrivateKey().getEncoded()))
            .append("\n-----END PRIVATE KEY-----\n")
            ;
        }
    }

    public static PublicKeyEntry decodePublicKey(String header, String body)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] decoded = Base64.getMimeDecoder().decode(body);

        // Expecting ASN.1 structure:
        //
        // SEQUENCE
        //   SEQUENCE
        //     OID <-- key algorithm

        String algorithm;

        ASN1Stream a1s = new ASN1Stream(decoded);

        if(ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
           && -1 != a1s.nextLength()
           && ASN1Stream.Tag.SEQUENCE.equals(a1s.nextTag())
           && -1 != a1s.nextLength()
           && ASN1Stream.Tag.OID.equals(a1s.nextTag())) {
            String oid = a1s.getOID(a1s.nextLength());

            algorithm = ALGORITHM_OIDS.get(oid);

            if(null == algorithm) {
                throw new IllegalArgumentException("Unrecognized algorithm OID: " + oid);
            }
        } else {
            System.err.println("Confused; dumping ASN.1 data");

            ASN1Stream.dump(decoded);

            algorithm = null;
        }

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

        PublicKey pk = keyFactory.generatePublic(keySpec);

        return new PublicKeyEntry(header, body, algorithm, pk);
    }

    public static class PublicKeyEntry extends Entry {
        private String algorithm;
        private PublicKey key;

        public PublicKeyEntry(String header, String body, String algorithm, PublicKey key)
        {
            super(header, body);

            this.algorithm = algorithm;
            this.key = key;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public PublicKey getPublicKey() {
            return key;
        }

        public String toString() {
            PublicKey pk = getPublicKey();

            if(pk instanceof ECPublicKey) {
                EllipticCurve curve = ((ECPublicKey)key).getParams().getCurve();

                EllipticCurve better = NamedCurve.forCurve(curve);

                if(null != better) {
                    curve = better;
                } else {
                    System.out.println(getBody());
                    /*
                    System.out.println("Couldn't find matching curve for " + curve);
                    System.out.println("A: " + curve.getA().toString(16));
                    System.out.println("B: " + curve.getB().toString(16));
                    if(curve.getField() instanceof ECFieldFp) {
                        ECFieldFp theirField = (ECFieldFp)curve.getField();
                        System.out.println("P=" + theirField.getP().toString(16));
                    } else if(curve.getField() instanceof ECFieldF2m) {
                        ECFieldF2m theirField = (ECFieldF2m)curve.getField();
                        System.out.println("M=" + theirField.getM());
                        System.out.println("ks=" + Arrays.toString(theirField.getMidTermsOfReductionPolynomial()));
                    }
                    /*

                    System.out.println("I think it's this curve: ");
                    EllipticCurve mine = NamedCurve.forOID("1.2.840.10045.3.0.11");
                    System.out.println("equals? " + mine.equals(curve));

                    System.out.println("A: " + mine.getA().toString(16));
                    System.out.println("B: " + mine.getB().toString(16));
                    if(mine.getField() instanceof ECFieldFp) {
                        ECFieldFp theirField = (ECFieldFp)mine.getField();
                        System.out.println("P=" + theirField.getP().toString(16));
                    } else if(mine.getField() instanceof ECFieldF2m) {
                        ECFieldF2m theirField = (ECFieldF2m)mine.getField();
                        System.out.println("M=" + theirField.getM());
                        System.out.println("ks=" + Arrays.toString(theirField.getMidTermsOfReductionPolynomial()));
                    }
/*                    */
                    //System.exit(1);
                }
                ECParameterSpec spec = ((ECPublicKey)pk).getParams();
                int len;
                if (spec != null) {
                    len = spec.getOrder().bitLength(); // does this really return something we expect?
                } else {
                    // We support the key, but we don't know the key length
                    len = 0;
                }

                return getHeader() + ", " + roundBitsToByteBits(len) + " bits, curve=" + curve;
//                return getHeader() + ", " + roundBitsToByteBits(((ECPrivateKey)pk).getS().bitLength()) + " bits";
            } else if(pk instanceof RSAPublicKey) {
                return getHeader() + ", " + algorithm + " " + (((RSAPublicKey)pk).getModulus().bitLength() + " bits");
            } else if(pk instanceof DSAPublicKey) {
                return getHeader() + ", " + algorithm + " " + (((DSAPublicKey)pk).getParams().getP().bitLength() + " bits");
            } else if(pk instanceof DHPublicKey) {
                return getHeader() + ", " + algorithm + " " + (((DHPublicKey)pk).getParams().getP().bitLength() + " bits");
            } else {
                return getHeader() + ", " + algorithm + ", key=" + key;
            }
        }
    }

    private static int roundBitsToByteBits(int b) {
        if(0 == (b & 0x7)) {
            return b;
        } else {
            return (b + 8) & 0xfff8; // Round up to the nearest 8
        }
    }

    public static class ECParametersEntry extends Entry {
        private final ECParameterSpec spec;
        public ECParametersEntry(String header, String body, ECParameterSpec spec) {
            super(header, body);

            this.spec = spec;
        }

        public ECParameterSpec getECParameterSpec() {
            return spec;
        }
    }

    private int maxEntryLength = 4096;
    private final InputStream in;
    private final Reader reader;
    private PasswordProvider passwordProvider;

    /**
     * Creates a new PEMFile from a Reader.
     *
     * @param in The source data to read.
     */
    public PEMFile(Reader in) {
        this.in = null;
        this.reader = in;
    }

    /**
     * Creates a new PEMFile from an InputStream.
     *
     * @param in The source data to read.
     */
    public PEMFile(InputStream in) {
        this.in = in;
        this.reader = null;
    }

    /**
     * Sets the PasswordProvider for this PEMFile.
     *
     * This PasswordProvider will be used to request passwords if any encrypted
     * Entries are found in the PEM stream.
     *
     * @param passwordProvider The PasswordProvider to use to obtain passwords.
     */
    public void setPasswordProvider(PasswordProvider passwordProvider) {
        this.passwordProvider = passwordProvider;
    }

    /**
     * Gets the PasswordProvider for this PEMFile.
     *
     * @return The PasswordProvider to use to obtain passwords.
     */
    public PasswordProvider getPasswordProvider() {
        return passwordProvider;
    }

    /**
     * Gets the next entry in the PEM file.
     *
     * @return A subclass of Entry, depending upon the type of data in the entry.
     *
     * @throws IOException If there is a problem reading the input.
     *
     * @throws GeneralSecurityException If there is a problem with the cryptography.
     */
    public Entry getNext()
        throws IOException, GeneralSecurityException
    {
        if(!scanFor("-----BEGIN ")) {
            return null;
        }

        String header = readUntil("-----");

        if(null == header) {
            return null;
        }

        String body = readUntil("-----END " + header + "-----");

        if(null == body) {
            return null;
        }

        return Entry.decode(header, body, getPasswordProvider());
    }


    private boolean scanFor(String token)
        throws IOException
    {
        if(null == token || 0 == token.length()) {
            throw new IllegalArgumentException("Must search for an actual token");
        }

        final int tokenLength = token.length();
        int tokenPos = 0;
        int tokenChar = token.charAt(0);

        while(true) {
            int ch = read();

            // System.out.println("scanFor: token (" + token + ") length=" + tokenLength + ", tokenPos=" + tokenPos + ", ch=" + ch);

            if(-1 == ch) {
                return false;
            }
            if(ch == tokenChar) {
                ++tokenPos;
                if(tokenPos >= tokenLength) {
                    // All done!
                    return true;
                }
                tokenChar = token.charAt(tokenPos);
            } else {
                tokenPos = 0;
                tokenChar = token.charAt(0);
            }
        }
    }

    /**
     * Reads a single byte from either the InputStream or the Reader.
     *
     * @return The value of {@link InputStream#read} or {@link Reader.read}.
     *
     * @throws IOException If there is an error reading the stream.
     *
     * @see InputStream.read
     * @see Reader.read
     */
    private int read() throws IOException {
        if(null != in) {
            return in.read();
        } else if(null != reader) {
            return reader.read();
        } else {
            throw new IllegalStateException("");
        }
    }

    private String readUntil(String token)
        throws IOException
    {
        if(null == token || 0 == token.length()) {
            throw new IllegalArgumentException("Must search for an actual token");
        }

        StringBuilder sb = new StringBuilder();

        final int tokenLength = token.length();
        int tokenPos = 0;
        int tokenChar = token.charAt(0);

        while(true) {
            int ch = read();

            // System.out.println("readUntil: token (" + token + ") length=" + tokenLength + ", tokenPos=" + tokenPos + ", ch=" + ch);

            if(-1 == ch) {
                return null;
            }

            if(sb.length() > (maxEntryLength - 1)) {
                throw new IOException("Reached maximum PEMFile entry length (" + maxEntryLength + ")");
            }

            sb.append((char)ch);
            if(ch == tokenChar) {
                ++tokenPos;
                if(tokenPos >= tokenLength) {
                    // All done! Remove trailing token
                    sb.setLength(sb.length() - tokenLength);
                    return sb.toString();
                }
                tokenChar = token.charAt(tokenPos);
            } else {
                tokenPos = 0;
                tokenChar = token.charAt(0);
            }
        }
    }
}
