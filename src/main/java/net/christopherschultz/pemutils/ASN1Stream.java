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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * An ASN.1 stream parser.
 *
 * This class is very basic, and not all tags are supported.
 *
 * This was written in order to read DER files, so it is not a "complete"
 * implementation of an ASN.1 parser by any account.
 *
 * Special thanks to the following people and tools for helping with this code:
 * - Wikipedia
 * - Lapo Luchini for his ASN.1 explorer tool found at https://lapo.it/asn1js/
 *
 *
 * @author Christopher Schultz
 */
public class ASN1Stream
{
    public enum Tag {
        BOOLEAN(0x01),
        INTEGER(0x02),
        BIT_STRING(0x03),
        OCTET_STRING(0x04),
        NULL(0x05),
        OID(0x06),
        // REAL(0x09),
        UTF8STRING (0x0c),
        PRINTABLE_STRING(0x13),
        IA5STRING(0x16),
        SEQUENCE(0x30),
        CONTEXT_0 (0xa0),
        CONTEXT_1 (0xa1),
        // SET(0x31)

        ;

        /*
Type    Tag number
(decimal)   Tag number
(hexadecimal)
INTEGER 2   02
BIT STRING  3   03
OCTET STRING    4   04
NULL    5   05
OBJECT IDENTIFIER   6   06
SEQUENCE and SEQUENCE OF    16  10
SET and SET OF  17  11
PrintableString 19  13
T61String   20  14
IA5String   22  16
UTCTime 23  17
         */
        int tagId;
        Tag(int tagId) {
            this.tagId = tagId;
        }
        int getId() {
            return tagId;
        }

        // TODO: Improve this
        static Tag fromTagId(int id) {
            for(Tag t : Tag.values()) {
                if(id == t.getId()) {
                    return t;
                }
            }
            throw new IllegalArgumentException("Unknown tag id: 0x" + Integer.toHexString(id));
        }
    }

    private InputStream in;

    /**
     * Creates a new ASN1Stream from an InputStream.
     *
     * @param in The source data to read.
     */
    public ASN1Stream(InputStream in) {
        this.in = in;
    }

    /**
     * Creates a new ASN1Stream from a byte array.
     *
     * @param in The source data to read.
     */
    public ASN1Stream(byte[] in) {
        this(new ByteArrayInputStream(in));
    }

    /**
     * Gets the next ASN.1 tag in the stream.
     *
     * @return The next ASN.1 tag in the stream.
     *
     * @throws IOException If there is a problem reading from the stream.
     * @throws IllegalArgumentException If the tag is not recognized.
     */
    public Tag nextTag() throws IOException {
        int b = in.read();
        if(-1 == b) {
            return null;
        } else {
            return Tag.fromTagId(b);
        }
    }

    /**
     * Gets the length of the current tag's data.
     *
     * @return The length of the current tag's data.
     *
     * @throws IOException If there is a problem reading from the input.
     * @throws IllegalArgumentException If the length of the tag is not supported.
     */
    public long nextLength() throws IOException {
        int c = in.read();

        if(-1 == c) {
            return -1;
        }
        byte b = (byte)c;
        if(0 == (b & 0x80)) {
            // Definite, short
            return c;
        } else {
            // Truncate MSB
            b = (byte)(b & 0x7f);

            if(0 == b) {
                // Indefinite
                throw new UnsupportedOperationException("Indefinite lengths are not supported");
            } else if(0x7f == b) {
                // Reserved
                throw new IllegalArgumentException("Use of reserved length: 0x" + Integer.toHexString(c));
            } else {
                // Definite, long
                if(8 < b)  {
                    throw new UnsupportedOperationException("Cannot handle 'definite, long' length encodings more than 8 bytes (yet): " + Integer.toHexString(c));
                }

                long length = 0;
                for(int i=0; i<b; ++i) {
                    length <<= 8;
                    c = in.read();
                    if(-1 == c) {
                        throw new IOException("EOF while reading definite long length encoding");
                    }
                    length |= c & 0xff;
                }

                return length;
            }
        }
    }

    /**
     * Skips <code>length</code> bytes of the input stream.
     *
     * @param length The number of bytes to skip.
     *
     * @return The number of bytres actually skipped.
     *
     * @throws IOException If the input does not support seek,
     *         or if there is another problem skipping the bytes.
     */
    public long skip(long len) throws IOException {
        return in.skip(len);
    }

    /**
     * Consumes the next <code>length</code> bytes and returns them as a
     * byte array.
     *
     * @param length The number of bytes to consume.
     *
     * @return The next <code>length</code> bytes of the stream as a byte array.
     *
     * @throws IOException If there is a problem reading from the input.
     */
    public BigInteger getInt(long length) throws IOException {
        if(1 == length) {
            int c = in.read();

            if(-1 == c) {
                throw new IOException("EOF while reading integer value");
            }

            return BigInteger.valueOf(c & 0xf0);
        }

        if(length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Cannot read integer values larger than " + Integer.MAX_VALUE + " bytes");
        }

        return new BigInteger(getBytes(length));
    }

    /**
     * Parses the next tag in the stream as an INTEGER and consumes
     * its length.
     *
     * @return A BigInteger value
     *
     * @throws IOException If there is a problem reading from the input.
     * @throws IllegalStateException If the next tag in the stream is not an INTEGER.
     *
     * @see #getInt(long)
     */
    public BigInteger getInt() throws IOException {
        Tag tag = nextTag();
        if(Tag.INTEGER != tag) {
            throw new IllegalStateException("Found tag " + tag + " when attempting to read " + Tag.INTEGER);
        }

        return getInt(nextLength());
    }

    /**
     * Consumes the next <code>length</code> bytes and returns them as a
     * byte array.
     *
     * @param length The number of bytes to consume.
     *
     * @return The next <code>length</code> bytes of the stream as a byte array.
     *
     * @throws IOException If there is a problem reading from the input.
     */
    public byte[] getBytes(long length) throws IOException {
        if(length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Value too long: " + length);
        }

        int len = (int)length;
        byte[] bytes = new byte[len];
        // System.out.println("Expecting to read " + len + " bytes");
        int read = 0;
        int readl = 0;

        while(-1 != (read = in.read(bytes, readl, len - readl)) && readl < len) {
            // System.out.println(": read " + read + " bytes of " + len);
            readl+= read;
        }
        if(-1 == read && readl < length) {
            throw new IOException("End of file reached waiting for " + (len - readl) + " bytes");
        }

        return bytes;
    }

    /**
     * Parses the next tag in the stream as an OCTET_STRING and consumes
     * its length.
     *
     * @return A byte array
     *
     * @throws IOException If there is a problem reading from the input.
     * @throws IllegalStateException If the next tag in the stream is not an OCTET_STRING.
     *
     * @see #getBytes(long)
     */
    public byte[] getBytes() throws IOException {
        Tag tag = nextTag();
        if(Tag.OCTET_STRING != tag) {
            throw new IllegalStateException("Found tag " + tag + " when attempting to read " + Tag.OCTET_STRING);
        }

        return getBytes(nextLength());
    }

    /**
     * Consumes the next <code>length</code> bytes and returns them as a
     * UTF-8 String.
     *
     * @param length The number of bytes to consume.
     *
     * @return The UTF-8-encoded string at the current position in the file.
     *
     * @throws IOException If there is a problem reading from the input.
     */
    public String getUTF8String(long length) throws IOException {
        return new String(getBytes(length), StandardCharsets.UTF_8);
    }

    /**
     * Consumes the next <code>length</code> bytes and returns them as an
     * ASCII String.
     *
     * @param length The number of bytes to consume.
     *
     * @return The "printable" string at the current position in the file.
     *
     * @throws IOException If there is a problem reading from the input.
     */
    public String getPrintableString(long length) throws IOException {
        return new String(getBytes(length), StandardCharsets.US_ASCII);
    }

    /**
     * Consumes the next <code>length</code> bytes and returns them as an
     * ASCII String.
     *
     * @param length The number of bytes to consume.
     *
     * @return The ASCII string at the current position in the file.
     *
     * @throws IOException If there is a problem reading from the input.
     */
    public String getIA5String(long length) throws IOException {
        return new String(getBytes(length), StandardCharsets.US_ASCII);
    }

    /**
     * Consumes the next <code>length</code> bytes and returns them as an
     * OID String.
     *
     * @param length The number of bytes to consume.
     *
     * @return The OID at the current position in the file, as a String.
     *
     * @throws IOException If there is a problem reading from the input.
     */
    public String getOID(long length) throws IOException {
        int c = in.read();

        if(-1 == c) {
            throw new IOException("EOF reading OID");
        }

        StringBuilder sb = new StringBuilder();
        // First two elements of the OID (e.g. "1.2") are in the first byte.
        sb.append(c / 40); // Yes, this is correct
        sb.append('.');
        sb.append(c % 40); // Yes, this, too, is correct

        // Now, https://en.wikipedia.org/wiki/Variable-length_quantity
        for(long i=length - 1; i > 0; i--) {
            c = in.read();
            if(-1 == c) {
                throw new IOException("EOF reading OID");
            }

            if(0 == (c & 0x80)) {
                /*
                 * Looks like ASN.1 doesn't do signed numbers in OIDs
                if(0 != (c & 0x40)) {
                    // Sign bit is in the 7th bit
                    c = - (c & 0x2f);
                }
                 */
                sb.append('.');
                sb.append(c);
            } else {
                // Multi-byte value
                int count = 1;
                long l;
                /*
                     // Looks like ASN.1 doesn't do signed numbers in OIDs
                    if(0 != (c & 0x40)) {
                        // Sign bit is in the 7th bit
                        l = - (c & 0x3f);
                    } else {
                        l = c & 0x3f;
                    }
                 */

                l = c & 0x7f;

                // ce 3d
                // 1100 1110  0011 1101
                //  100 1110   011 1101
                //   10 0111  0011 1101

                do {
                    if(i <= 0) {
                        throw new IllegalStateException("Failed to completely read VLQ before running out of length bytes");
                    }
                    i--;
                    ++count;
                    if(8 < count) {
                        throw new UnsupportedOperationException("Cannot handle OID node with more than 8 bytes");
                    }
                    l <<= 7;

                    c = in.read();
                    if(-1 == c) {
                        throw new IOException("EOF reading OID");
                    }

                    l |= (c & 0x7f);
                } while(0x80 == (c & 0x80) && i>0);

                sb.append('.');
                sb.append(l);
            }
        }

        return sb.toString();
    }

    /**
     * Parses the next tag in the stream as an OID and consumes its length.
     *
     * @return A String
     *
     * @throws IOException If there is a problem reading from the input.
     * @throws IllegalStateException If the next tag in the stream is not an OID.
     *
     * @see #getOID(long)
     */
    public String getOID() throws IOException {
        Tag tag = nextTag();
        if(Tag.OID != tag) {
            throw new IllegalStateException("Found tag " + tag + " when attempting to read " + Tag.OID);
        }

        return getOID(nextLength());
    }

    public void dump(PrintStream out) throws IOException {
        dump("", Long.MAX_VALUE, out);
    }

    /*
SEQUENCE {
   INTEGER 0x00 (0 decimal)
   SEQUENCE {
      OBJECTIDENTIFIER 1.3.101.110
      NULL
   }
   OCTETSTRING 0420c1df30f49e435a42b4f89cfdc357cc3d69cb2c7b70fc301bb9816979e20ff759
}
     */
    private void dump(String indent, long byteCount, PrintStream out) throws IOException {
        ASN1Stream.Tag tag = nextTag();

        while(null != tag) {
            long itemlen = nextLength();
            //System.out.println("indent=>" + indent + "< bytecount=" + byteCount + " tag=" + tag +", len=" + itemlen);

            out.print(indent);
            out.print(tag);

            if(ASN1Stream.Tag.SEQUENCE == tag || ASN1Stream.Tag.CONTEXT_0 == tag || ASN1Stream.Tag.CONTEXT_1 == tag) {
                out.print(" (len=");
                out.print(itemlen);
                out.print(")");
                out.println();
                // Don't skip; descend into
                dump(indent + "  ", itemlen, out);
            } else if(ASN1Stream.Tag.OID == tag) {
                out.print(" ");
                out.println(getOID(itemlen));
            } else if(ASN1Stream.Tag.INTEGER == tag) {
                BigInteger value = getInt(itemlen);
                out.print(" 0x");
                out.print(value.toString(16));
                out.print(" (");
                out.print(value.toString(10));
                out.println(" decimal)");
            } else if(ASN1Stream.Tag.UTF8STRING == tag) {
                out.println("value=" + getUTF8String(itemlen));
            } else if(ASN1Stream.Tag.OCTET_STRING == tag) {
                byte[] bytes = getBytes(itemlen);
                out.print(" 0x");
                out.println(toHexString(bytes));
                // out.println("ASCII=" + new String(bytes, StandardCharsets.US_ASCII));
            } else if(ASN1Stream.Tag.PRINTABLE_STRING == tag) {
                out.print(" \"");
                out.print(getPrintableString(itemlen));
                out.println('"');
            } else if(ASN1Stream.Tag.IA5STRING == tag) {
                out.println("value=" + getIA5String(itemlen));
            } else if(ASN1Stream.Tag.NULL == tag) {
                out.println();
                byteCount = itemlen; // Cause this method to end
            } else {
                out.println(" [Skipping " + itemlen + " bytes]");
                skip(itemlen);
            }

            byteCount -= itemlen;
            if(byteCount > 0) {
                tag = nextTag();
            } else {
                //out.println("Finished with indent >" + indent + "<");
                tag = null; // End processing
            }
        }
//        out.println("Got null tag to finish file");
    }

    /**
     * Dumps the provided data as a set of ASN.1 tags and values.
     *
     * @param data The data to dump
     *
     * @throws IOException If there is a problem reading the data.
     */
    public static void dump(byte[] data) throws IOException {
        ASN1Stream a1s = new ASN1Stream(data);

        a1s.dump(System.out);
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Dumps binary data in a "pretty" style.
     *
     * @param bytes The bytes to dump.
     * @param columns The number of columns to divide the data into,
     *                typically 16 or 32.
     */
    public static void dump(byte[] bytes, int columns) {
        if(1 > columns) {
            throw new IllegalArgumentException("Columns must be > 0");
        }
        if(1 == (columns & 0x1)) {
            throw new IllegalArgumentException("Columns must be an even number");
        }
        for(int i=0; i<bytes.length; ++i) {
            if(0 < i) {
                if(0 == (i % columns)) {
                    System.out.println();
                } else if(0 == i % 16) {
                    System.out.print("    ");
                }
            }

            byte b = bytes[i];

            if(0 == (b & 0xf0)) {
                System.out.print("0");
                System.out.print(Integer.toHexString(b & 0x0f));
            } else {
                System.out.print(Integer.toHexString(b & 0xff));
            }
            System.out.print(" ");
        }
        if(0 != (bytes.length % 16)) {
            System.out.println();
        }
    }

    /**
     * Converts a byte array into a series of hex digits.
     *
     * @param bytes The byte array to convert to a String.
     *
     * @return The hex-string representation of the byte array.
     *
     * @see #fromHexString(String)
     */
    static String toHexString(byte[] bytes) {
        final int len=bytes.length;
        StringBuilder sb = new StringBuilder(len << 1);

        for(int i=0; i<len; ++i) {
            int b = bytes[i];
            sb.append(HEX[ (b >>> 4) & 0x0f ]);
            sb.append(HEX[ (b      ) & 0x0f ]);
        }
        return sb.toString();
    }

    /**
     * Converts a string of hex digits into a byte array.
     *
     * @param s The hex-string to parse.
     *
     * @return An array of bytes.
     *
     * @see #toHexString(byte[])
     */
    static byte[] fromHexString(String s) {
        int len = s.length();
        byte[] b = new byte[len / 2];
        for (int src = 0, dst = 0; src < len; ++dst) {
            int hi = Character.digit(s.charAt(src++), 16);
            int lo = Character.digit(s.charAt(src++), 16);
            b[dst] = (byte) (hi << 4 | lo);
        }
        return b;
    }

    public static void main(String[] args) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int c;

        while(-1 != (c = System.in.read(buffer))) {
            baos.write(buffer, 0, c);
        }

        ASN1Stream.dump(baos.toByteArray());

        baos.close(); // :)
    }
}