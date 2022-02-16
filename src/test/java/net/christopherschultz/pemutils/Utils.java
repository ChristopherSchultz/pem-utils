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
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.christopherschultz.pemutils.ASN1Stream;
import net.christopherschultz.pemutils.NamedCurve;

/**
 * Utilities to generate curve definitions and sample data.
 *
 * This class is entirely unnecessary for use of this library.
 *
 * @author Christopher Schultz
 */
public class Utils {
    /**
     * Dumps the entries in a PEM file found on standard input.
     *
     * @param args Ignored
     *
     * @throws Exception If any error occur.
     */
    public static void main(String[] args) throws Exception {
        if(args.length > 0 && "-curvedefs".equals(args[0])) {
            generateCurveDefinitions();
        } else if(args.length > 0 && "-samples".equals(args[0])) {
            generateEllipticCurveSamples();
        } else {
            System.out.println("Run me with -curvedefs or -samples");
        }
    }

    private static void generateEllipticCurveSamples() throws GeneralSecurityException {
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        System.setProperty("jdk.disabled.namedCurves", "");
        Security.setProperty("crypto.policy", "unlimited"); // For Java 9+
        System.setProperty("jdk.sunec.disableNative", "false");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

        for(String curve : new String[] {"X9.62 c2tnb191v1",
                "X9.62 c2tnb191v2",
                "X9.62 c2tnb191v3",
                "X9.62 c2tnb239v1",
                "X9.62 c2tnb239v2",
                "X9.62 c2tnb239v3",
                "X9.62 c2tnb359v1",
                "X9.62 c2tnb431r1",
                "X9.62 prime192v2",
                "X9.62 prime192v3",
                "X9.62 prime239v1",
                "X9.62 prime239v2",
                "X9.62 prime239v3",
                "brainpoolP160r1",
                "brainpoolP192r1",
                "brainpoolP224r1",
                "brainpoolP256r1",
                "brainpoolP320r1",
                "brainpoolP384r1",
                "brainpoolP512r1",
                "secp112r1",
                "secp112r2",
                "secp128r1",
                "secp128r2",
                "secp160k1",
                "secp160r1",
                "secp160r2",
                "secp192k1",
                "secp192r1",
                "secp224k1",
                "secp224r1",
                "secp256k1",
                "secp256r1",
                "secp384r1",
                "secp521r1",
                "sect113r1",
                "sect113r2",
                "sect131r1",
                "sect131r2",
                "sect163k1",
                "sect163r1",
                "sect163r2",
                "sect193r1",
                "sect193r2",
                "sect233k1",
                "sect233r1",
                "sect239k1",
                "sect283k1",
                "sect283r1",
                "sect409k1",
                "sect409r1",
                "sect571k1",
                "sect571r1",
        }) {
            try {
                kpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
                KeyPair keyPair = kpg.generateKeyPair();

                System.out.println("# " + curve);
/*
                System.out.println("-----BEGIN EC PARAMETERS-----");
                System.out.println("-----END EC PARAMETERS-----");
*/
                System.out.println("-----BEGIN PRIVATE KEY-----");
                System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
                System.out.println("-----END PRIVATE KEY-----");

                System.out.println("-----BEGIN PUBLIC KEY-----");
                System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
                System.out.println("-----END PUBLIC KEY-----");

                printEncryptedPrivateKey(keyPair.getPrivate(), System.out);

                // TODO: Create a certificate as well

            } catch (InvalidAlgorithmParameterException iape) {
                // Curve not supported
                System.out.println("## Invalid curve: " + curve);
            } catch (ProviderException pe) {
                if(pe.getCause() instanceof InvalidAlgorithmParameterException) {
                    // Curve not supported
                    System.out.println("## Invalid curve: " + curve);
                }
            }
        }

        for(String curve : new String[] { "X25519", "X448" } ) {
            kpg = KeyPairGenerator.getInstance(curve);

            kpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            System.out.println("# " + curve);
/*
            System.out.println("-----BEGIN EC PARAMETERS-----");
            System.out.println("-----END EC PARAMETERS-----");
*/
            System.out.println("-----BEGIN PRIVATE KEY-----");
            System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            System.out.println("-----END PRIVATE KEY-----");

            System.out.println("-----BEGIN PUBLIC KEY-----");
            System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            System.out.println("-----END PUBLIC KEY-----");

            printEncryptedPrivateKey(keyPair.getPrivate(), System.out);
        }

        // DSA
        // RSA
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // No need to have very strong keys
        KeyPair keyPair = kpg.generateKeyPair();
        System.out.println("# RSA-2048");

        System.out.println("-----BEGIN PRIVATE KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("-----END PRIVATE KEY-----");
        System.out.println("-----BEGIN PUBLIC KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("-----END PUBLIC KEY-----");

        kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024); // No need to have very strong keys
        keyPair = kpg.generateKeyPair();
        System.out.println("# DSA-1024");

        System.out.println("-----BEGIN PRIVATE KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("-----END PRIVATE KEY-----");
        System.out.println("-----BEGIN PUBLIC KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("-----END PUBLIC KEY-----");

        kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(1024); // No need to have very strong keys
        keyPair = kpg.generateKeyPair();
        System.out.println("# DH-1024");

        System.out.println("-----BEGIN PRIVATE KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("-----END PRIVATE KEY-----");
        System.out.println("-----BEGIN PUBLIC KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("-----END PUBLIC KEY-----");

        kpg = KeyPairGenerator.getInstance("RSASSA-PSS");
        kpg.initialize(1024); // No need to have very strong keys
        keyPair = kpg.generateKeyPair();
        System.out.println("# RSASSA-PSS-1024");

        System.out.println("-----BEGIN PRIVATE KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("-----END PRIVATE KEY-----");
        System.out.println("-----BEGIN PUBLIC KEY-----");
        System.out.println(Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("-----END PUBLIC KEY-----");
    }

    private static void generateCurveDefinitions() throws GeneralSecurityException {
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        System.setProperty("jdk.disabled.namedCurves", "");
        Security.setProperty("crypto.policy", "unlimited"); // For Java 9+
        System.setProperty("jdk.sunec.disableNative", "false");

        System.out.println("Running generateECdata on Java " + System.getProperty("java.version"));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

        for(String curve : new String[] {"X9.62 c2tnb191v1",
                "X9.62 c2tnb191v2",
                "X9.62 c2tnb191v3",
                "X9.62 c2tnb239v1",
                "X9.62 c2tnb239v2",
                "X9.62 c2tnb239v3",
                "X9.62 c2tnb359v1",
                "X9.62 c2tnb431r1",
                "X9.62 prime192v2",
                "X9.62 prime192v3",
                "X9.62 prime239v1",
                "X9.62 prime239v2",
                "X9.62 prime239v3",
                "brainpoolP160r1",
                "brainpoolP192r1",
                "brainpoolP224r1",
                "brainpoolP256r1",
                "brainpoolP320r1",
                "brainpoolP384r1",
                "brainpoolP512r1",
                "secp112r1",
                "secp112r2",
                "secp128r1",
                "secp128r2",
                "secp160k1",
                "secp160r1",
                "secp160r2",
                "secp192k1",
                "secp192r1",
                "secp224k1",
                "secp224r1",
                "secp256k1",
                "secp256r1",
                "secp384r1",
                "secp521r1",
                "sect113r1",
                "sect113r2",
                "sect131r1",
                "sect131r2",
                "sect163k1",
                "sect163r1",
                "sect163r2",
                "sect193r1",
                "sect193r2",
                "sect233k1",
                "sect233r1",
                "sect239k1",
                "sect283k1",
                "sect283r1",
                "sect409k1",
                "sect409r1",
                "sect571k1",
                "sect571r1",
        }) {
            try {
                kpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
                KeyPair keyPair = kpg.generateKeyPair();
                ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

                ECParameterSpec params = privateKey.getParams();
                EllipticCurve ec = params.getCurve();

                if(null == NamedCurve.forCurve(ec)) {
                    ECField field = ec.getField();
                    BigInteger p, a, b, x, y, n;
                    int m;
                    int[] ks;
                    int h;
                    byte[] seed;

                    if(field instanceof ECFieldFp) {
                        p = ((ECFieldFp)field).getP();
                        ks = null;
                        m = 0;
                    } else if(field instanceof ECFieldF2m){
                        ECFieldF2m f2m = (ECFieldF2m)field;
                        m = f2m.getM();
                        ks = f2m.getMidTermsOfReductionPolynomial();
/*
                        System.out.println("Curve " + curve + " has f2m with characteristics: ");
                        System.out.println("size=" + f2m.getFieldSize());
                        System.out.println("M=" + f2m.getM());
                        System.out.println("rp=" + f2m.getReductionPolynomial());
                        System.out.println("Terms=" + Arrays.toString(f2m.getMidTermsOfReductionPolynomial()));
*/
                        p = null;
                    } else {
                        p = null;
                        ks = null;
                        m = 0;
                    }
                    a = ec.getA(); // a
                    b = ec.getB(); // b

                    x = params.getGenerator().getAffineX(); // x
                    y = params.getGenerator().getAffineY(); // y

                    h = params.getCofactor(); // h
                    n = params.getOrder(); // n

                    seed = ec.getSeed();

                    /*
                        new NamedCurve("1.3.132.0.35",
                                Arrays.asList("secp521r1", "ansip521r1", "NIST P-521", "P-521"),
                                new BigInteger("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
                                new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16),
                                new BigInteger("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
                                new BigInteger("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
                                new BigInteger("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
                                new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16),
                                0x1,
                                ASN1Stream.fromHexString("D09E8800291CB85396CC6717393284AAA0DA64BA")
                                ),
                     */
                    if(null == p) {
                        System.out.println("new NamedCurve(\"[oid]\",\n"
                                + "Arrays.asList(\"" + curve + "\"),\n"
                                + m + ",\n"
                                + "new int[] { " + toIntList(ks) + " },\n"
                                + "new BigInteger(\"" + a.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + b.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + x.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + y.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + n.toString(16) + "\", 16),\n"
                                + "0x" + Integer.toHexString(h) + ",\n"
                                + ((null == seed) ? "null" : "ASN1Stream.fromHexString(\"" + ASN1Stream.toHexString(seed) + "\")")
                                + "\n),");
                    } else {
                        System.out.println("new NamedCurve(\"[oid]\",\n"
                                + "Arrays.asList(\"" + curve + "\"),\n"
                                + "new BigInteger(\"" + p.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + a.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + b.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + x.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + y.toString(16) + "\", 16),\n"
                                + "new BigInteger(\"" + n.toString(16) + "\", 16),\n"
                                + "0x" + Integer.toHexString(h) + ",\n"
                                + ((null == seed) ? "null" : "ASN1Stream.fromHexString(\"" + ASN1Stream.toHexString(seed) + "\")")
                                + "\n),");
                    }
                } else {
                    System.err.println("// Known curve: " + curve + "; skipping");
                }
            } catch (InvalidAlgorithmParameterException iape) {
                // Curve not supported
                System.out.println("Invalid curve: " + curve);
            } catch (ProviderException pe) {
                if(pe.getCause() instanceof InvalidAlgorithmParameterException) {
                    // Curve not supported
                    System.out.println("Invalid curve: " + curve);
                }
            }
        }

        for(String curve : new String[] { "X25519", "X448" }) {
            kpg = KeyPairGenerator.getInstance(curve);

            kpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();

            // TODO: Deal with the XEC-type keys
            /*
            ECPrivateKey privKey = (ECPrivateKey)keyPair.getPrivate();
            System.out.println("curve=" + privKey.getParams().getCurve());
            java.security.interfaces.XECPrivateKey key = (java.security.interfaces.XECPrivateKey)keyPair.getPrivate();
            System.out.println("Curve " + curve + " private key is of type " + key.getClass().getName());
            System.out.println("curve " + curve + " scalar=" + ASN1Stream.toHexString(key.getScalar().get()) + ", params=" + key.getParams()+ " (" + key.getParams().getClass().getName() + ")");
*/
//            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        }
    }

    private static void printEncryptedPrivateKey(PrivateKey pk, PrintStream out) throws GeneralSecurityException {
        // These KDF settings don't really matter
        byte[] salt = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        int iterations = 10;
        String password = "secret";

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA1");

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, 24 * 8 /* Why is this fixed? */);

        SecretKey secretKeyPbkdf = secretKeyFactory.generateSecret(pbeKeySpec);

        String baseEncryptionAlgorithm = "DESede"; // Without block cipher mode or padding info
        SecretKey secretKey = new SecretKeySpec(secretKeyPbkdf.getEncoded(), baseEncryptionAlgorithm);

        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new PBEParameterSpec(salt, iterations));

        byte[] encryptedKey = cipher.doFinal(pk.getEncoded());

        try {
            out.println("-----BEGIN ENCRYPTED PRIVATE KEY-----");
            out.println(Base64.getMimeEncoder().encodeToString(new EncryptedPrivateKeyInfo(cipher.getParameters(), encryptedKey).getEncoded()));
            out.println("-----END ENCRYPTED PRIVATE KEY-----");
        } catch (IOException ioe) {
            out.println("IOException: " + ioe.getMessage());
        }
    }
    private static String toIntList(int[] ints) {
        if(null == ints || 0 == ints.length) {
            return "";
        } else if(1 == ints.length) {
            return String.valueOf(ints[0]);
        } else {
            StringBuilder sb = new StringBuilder();
            for(int i=0; i<ints.length; ++i) {
                if(i > 0) { sb.append(','); }
                sb.append(String.valueOf(ints[i]));
            }
            return sb.toString();
        }
    }
}
