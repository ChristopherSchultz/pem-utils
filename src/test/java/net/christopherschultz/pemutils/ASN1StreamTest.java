package net.christopherschultz.pemutils;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import net.christopherschultz.pemutils.ASN1Stream;

public class ASN1StreamTest {

    @Before
    public void setUp() throws Exception {
    }

    private void testOIDParsing(String inputHex, String expectedOID) throws Exception {
        byte[] input = ASN1Stream.fromHexString(inputHex);

        ASN1Stream s = new ASN1Stream(input);
        assertEquals(ASN1Stream.Tag.OID, s.nextTag());
        long length = s.nextLength();
        assertEquals(expectedOID, s.getOID(length));
    }

    @Test
    public void testOIDc2tnb191v1Parsing() throws Exception {
        testOIDParsing("06032B656E", "1.3.101.110");
    }

    @Test
    public void testOIDX25519Parsing() throws Exception {
        testOIDParsing("06082A8648CE3D030005", "1.2.840.10045.3.0.5");
    }
}
