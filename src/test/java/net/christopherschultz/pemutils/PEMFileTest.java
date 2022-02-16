package net.christopherschultz.pemutils;
import static org.junit.Assert.*;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import net.christopherschultz.pemutils.PEMFile.ECParametersEntry;

/*
-----BEGIN EC PARAMETERS-----

-----BEGIN RSA PRIVATE KEY----- (possibly encrypted)
-----BEGIN ENCRYPTED PRIVATE KEY----- (EC, RSA, DSA)
-----BEGIN PRIVATE KEY----- (EC, RSA, DSA)

-----BEGIN EC PRIVATE KEY-----

 */
public class PEMFileTest {

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void testNullPEM() throws Exception {
        Collection<PEMFile.Entry> entries = PEMFile.decode(null);

        assertNull(entries);
    }

    @Test
    public void testEmptyPEM() throws Exception {
        Collection<PEMFile.Entry> entries = PEMFile.decode("");

        assertNotNull(entries);
        assertTrue(entries.isEmpty());
    }

    @Test
    public void testRSAPrivateKey() throws Exception {
        String pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIIJKQIBAAKCAgEA4oDNANHMtzvzOzcmBW8Kw9ML7oPmL4mJdf+4ASxwiQOfaTyw\n"
                + "+xRRDWwLAHG3xJDxVHTNGP8oTS+YGLOWLWcOe6jzlmBOpuFl766qVWs/Ts8b9Avy\n"
                + "YBLICnM0PJt/HDHXdqKpttqB5/6udqA/S9F56vF8e41EezG7fsmAwgstM9UX/D8C\n"
                + "e4NIkDBjJ02frsx3dDUHcjNtOQW2qqQT9QRDKQjaZQba4J2ooKHOiqATOldnF+1A\n"
                + "KgW/LfApLmfvfrBgghjB7HEF4XjlNXRrwT13ObTNwiy5lWsKWfD+3cK0MZDbrGPN\n"
                + "tBAvUBbAzR05iPJEhUu7ooxhiGYiQr81hzoGj/nxBStqPjCpSc4jq3p6I++juiMb\n"
                + "XyHNpVlEz+Q/LkBCCXClN3QDLYAaA7hs6l7RAP4+nerE25OR7ee2AcaTIDATxrsK\n"
                + "pgTfy/qHPZB/2uW6LqGxLyQblUGQH0fx262KYtUSu6hgOO4hn6cfzl++ZhMkqbO+\n"
                + "ZjbekLikrPiUsXTJJUbQSOA8mrx9Tu7cBrM9UtSDQiEYvAIpkjsnZoAbZCfT/OYH\n"
                + "IKxMo24xZP8SxgsbeylpsUVj+eDWnc+jMU1r8tZiuZfWXJjpTmv95K2FQIb7S+VD\n"
                + "JZ/ft4XZPyOtEw2yXIVBExg+16U7A08TmGusxwH7/2jQB1bDI6ZtgvtOQ30CAwEA\n"
                + "AQKCAgEAz+/Yw+jXHFyAFpuxXwmrA02LxaL3PirwtBBX11P51/8oaI9cFpR3OHA4\n"
                + "xWagg2dg9dzosQsF755C7mJn+zSCGkpnnWS6r/96+ogKPbLggrQmAGy7TTHQza8n\n"
                + "hIBoN/UVzgbU8VY2Lkoj1imVEkCzwVmCo1Z0SPjGHUZV204xaEU36M3btJI4mo6h\n"
                + "aGKdtvZkr51DQbcujUvOf2d0HtqT4WcMP/UEGXMDbLw/BgqgvE2jClc3MZzm/wBc\n"
                + "fgrS1iaL4sNhvHOiJ3U6T1Ga3uNTwflXb+xpT1/eN+XDxMhLbrmCwgc5wBWfqdHJ\n"
                + "nEQ5HpzzBMAa+MYRgAvrZgVt2cAOZoKyk3YC9XGiziS6tCUh9IgC9VSx6t/HRdPk\n"
                + "G2shBHLwtJFOclzw+v9Ba7BpV4c8ZVWCSYy5dKa8fj2Gl2a9NVqu4n5jHsS0/HAi\n"
                + "doTbYrWUGyvvANNt10jtGHRUBugBFZ8QJcEPn+g+41dr23IgrqqQeRQ+x7l8YV5j\n"
                + "TY7Ky+PyRVi2PVgrF6faMQNIXQtj31oschO3XbQOWf9BSVm36kzpzFGWiSuT0bmE\n"
                + "vAauPqC+xRAho9rJC3lMQNxPU/egoPTOZf7DJqwmD0ijR86puswRoZEVjcYQ4ZJz\n"
                + "CFLh+pqixkfQURbFqSMtVRsvDdGMhlS/ORMrhoYuiqJ2AI1yVkECggEBAPMuiSvp\n"
                + "Fdk7A3AOXbrQHLZX6wiOo9mumri65dd73DHBCInLFZY3UKOJ5Ub5cPU9u7VZCbXg\n"
                + "Y89qJDpVodvgzKmLPNCJBzZn6PtPk3O0+wKC+xYDrqrvEnjBd0YX+tewPLcOUGbA\n"
                + "0O8b6Ott95Enj7hdin+thapHBmDDr/FPfgvTzVGAywxnaBmN2QWpbIDA0TvAO0xL\n"
                + "PQxOkOgZcdOHHZbRXx56LPJQwvmCpR6gqyon0rroC+JAW6d3/pAP5oygP0F/Ya3k\n"
                + "MkA3PRO3M87ySLx4BPwU+M24PqeNCUdaoj36jlgt9A9uMiAGcmIXs2ffiGgYgXmN\n"
                + "En1Dg1Xg6BlSLnECggEBAO5xNJFE879kKn/dMaqnGRUA4cEz8e32UI1xVhUZ0TiC\n"
                + "HtOu8zaawaZqsC9ZnONJ9IWLX5gKqKesDJuXZ4pPfdVGVKn7Pl08eEGhHeWw6rdz\n"
                + "KLziu4SE3uaxSFqS1hvD+T5nHRmppegPI+slLLxv3fHE2NTqv5+Fl/S1s+6Txjy4\n"
                + "A/lLgAehglyrZypbSoqCWXJZTobYeemFJfPt5ojs+6vYitA/lK7PdlByBB25flWW\n"
                + "U3o50oFOqQJMe4NDNl4lY7FZF4gCQGg9d5NvTXpZsJxQl+jbQlkw9T+DODSaTykX\n"
                + "iLCivDiS5h2bkbGUZ8JFAVu2dUhYX3wKzXw/0MqPw80CggEAUJRW96ngh366gOMB\n"
                + "w+k52mH/i3JYcMUel5+2kVSFficMgTw+BuyFV+tVgdMdzuWJ0WmTgiS8bfopzvqZ\n"
                + "C5bNulBc8my1ax27YarYnTqXAhoMwRqvQgy9/i19LEi94cKQG8gudB3oHZMN9xUV\n"
                + "N4/4W4sDXZNN+0JVprKxFjDU/25LVnpqzc1l/TG3e9zMC03ZBweHnpw/ulg+Q+pK\n"
                + "gWEAOP1fm2W4hwKj2LGlrSRoEyvm8+/4IBxbQn7MZ0gdiPOAgl+HKmu3CvhC0Mmf\n"
                + "7S7zUyAh5rW8S86FVFezf2VU5Vyk1itD9+j3ywzX0hEwbXbwaC3WmURZoBBC8K35\n"
                + "uoo0wQKCAQEAvd4TN+IqHitK1Ep0dClfBaSQH+KXMR/EgPzQyTinq1Gh7noPXVnZ\n"
                + "/gRSi0HWdf674WNcGZvTNMEBwRvM7QvjbWL1o+1WebPfJpN/VRmNrcrbk50QKLQN\n"
                + "MrHUpZrrN2zUGebN+1NlsuXreiE+AEcr+or/BnxvXj1pBQlzX/T4E/2L3IVMS8dG\n"
                + "ITizi7zqHGUziKSorSPP4C2QTS8RNdNPjEWAM9eNM64rzl8b+/drLAfqLRfCEglq\n"
                + "91OjvqBUuJ8ZRW1mGX2BgAACKbqlfVnSEobykA+YQ6GCiLKanPiLNHNy+wR60KnY\n"
                + "55arazZ7cOy16iveNF96mTGY8ul1/vZ/uQKCAQBIMEyzQBb/0qvLQhNCGLRsFvsl\n"
                + "Mn5zGrrma7qGGRFdV1k32nlyX8gZIzR/XbXdlDhRNw+XqB47LFY8Bo0j+xuFg0TP\n"
                + "lys1d5B3xuqNGMzK8Fn5cVvqPxIl+E6sdBRM7cnyl3fs4BcC99SfRGeoS0AAfH+J\n"
                + "tw61KzDouTa3Qk/89h4IVO7TFM0oSKzT0kj9tbRu9aDBG63pGsLMlLiPIbn91zKP\n"
                + "ahU0vqUohkfQuqroiqVsolefErqDX14oeh+J+MybFVj63SoLEuL4hBpmT7dU+U+k\n"
                + "buNCxQqb0bN+ytYmU7MgwG8n6h0N6TnzvhJJugZnTRA4kN8NR9fKTjELBRb6\n"
                + "-----END RSA PRIVATE KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PrivateKeyEntry);
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof RSAPrivateKey);

        RSAPrivateKey rpk = (RSAPrivateKey)pk;

        assertEquals(4096, rpk.getModulus().bitLength());
    }

    @Test
    public void testRSAEncryptedPrivateKey() throws Exception {
        String pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "Proc-Type: 4,ENCRYPTED\n"
                + "DEK-Info: DES-EDE3-CBC,079F3858FC92E561\n"
                + "\n"
                + "zDD1HQoJEFcbS0RUoB8H0GEDyK07b3UDzf89ylnTLmRvoOS7du6eyAqsGxYJnkmr\n"
                + "+xsTAMxpyyQRMSOo58tZz+aqebDtFUjvyI3R7P0ZosIGs2GDS5qVbch+PiqpnbXi\n"
                + "y3GDG92j75qePGl6/NFWky0QrZ61W3ev+9gqnwUENHBR65PlH5qwhBNta8N0d9LU\n"
                + "iaxieBL7TILrslQiIlsAxPOJ+I/2ZljtsMaHwjmBL48zFooNtk7kPQkUSVSTDJ9A\n"
                + "+pJMbWjoc9otWFK/X1qpNf00s7/FlEVpLCqZKiAYcNgIky3ZNRnEUd4YKYBefCrl\n"
                + "7MWgb2epOOuP5DfTcJUr7TQH62GTEzoec+RH8KWW3HfZvwXeuxx6n7DiARx1SfUx\n"
                + "d+qChYWWwsQMOZGG5Upt3bG4lPZPrPya+7bIkoMrkYNY8GjvfInbL+66pMRyw1Db\n"
                + "AUXGbyR1Ov7uTI3fHsQw1EgV0mooTrFY2njPBpmrKYW/fxSuCZLAFE8wX2yGnnrX\n"
                + "8CXbolBE44jviH22nHsN5NodDPEtJfxmFG/0mmDhNhfeQhL2aAPYGezJmvrUQ8L6\n"
                + "GX15FYBhrvBgsakqaq2EkW1jTseNC++TW5KuRJln8vKcFMlwM2WTxddRq+cpJoOZ\n"
                + "pX63Sbp90eO9pXaKGEmIzGlM6l1FTVWKIpmyTG3Y6Uyx4qoFhoLQ2fLcKuq58PSq\n"
                + "0f5a0mRm4rhuuXKQVHJiQQEOIOtnS+9oUPuzXbKACfRmva3WZ44tByOb3tY2iwrY\n"
                + "PsJ7Ur3fhwLOxMtSVuitLF/4BVMcmorgWhRCpJqTcHFjxECYhnF8jMOYAlzQOQg2\n"
                + "raKZWbAXTG6NPUEqAVlJRFP4BacZKNiUbWP3dEKHDNIuoDCAGqdO5MU5jSy9x0e/\n"
                + "CPgDpNU9xw2JnmTT4VGZmn0xpfO8b8sim5y0vf/TQ6Z77/NNa3pJn+42jtbs+syS\n"
                + "5Z/Du1zKXTXhX2fYQc/6/lWIdXhjfJrOMK+siRPFJxdL1TdwfoLJMh3IbD/neEd9\n"
                + "KuiMM1D9PgqAqe12L3TDdF2JWzQ5gjxsTyMJzUrhXnAH0xKjll6Nck50uUnZh0n7\n"
                + "MHHM8kyWoLN3JUhjQauh8VeJVk+SLnhPXggclU4WKf+znLSWapWYO4z+ZH3px1sr\n"
                + "tyjFXxWPbMB9ZjS9WkSxJe/dQeAC4DDXKtzTLa/pbsw6g0AJAaQmYFFcasChgOoL\n"
                + "vKRjxE4IHAaotHDbKKGyhDDfeEOoBACrXO0iprR7YmSYC1+CqcUmgvVVlEcQTVxh\n"
                + "bXA/aozGuSaLc3HJzm31D+ww2u/fmxHTZqjIDJBS2ZFx+gNHo/KNfB/1aoODrsu8\n"
                + "lWIVJVv36sMyI8oYH2u4XahOeOu+aE9bcalKT09rTF+f84R6g4pib7lQc4Zf1mIY\n"
                + "CPmk7d/bDXNYsVIfKojFuGNCQf0NX2v2Bj/SVPBHOoAhHFKTn2ButTkUySh7ggZr\n"
                + "Jg4f3110E4AKpaXjdV0cBgluUvM3GVj1mc8lFe22wqdlpzgV9rRjn+US5VCydSe4\n"
                + "QWUmaxn8QCnIQrWmusCmE4XantCcYRE9f6YY4oYwMYQpqjYuIhxPkeItwv1wf6ll\n"
                + "yUtAmZ1zFQjzIAyD9oiPSMl7XxzR0baWAb2mGnZ68rStfatQFa7YwUFJW0Zf/0D8\n"
                + "dLBVYzf17wopfJNIHqOtt6OcRGK5+OMWQQJwh07DDeW2gPHiEjkFymSfv6yZesyN\n"
                + "/tQaTGyJC9Sxu6aUevWmrYwampseq7RA+CZxcleAWoQaO9c6UahcZmYUruQOq2ZO\n"
                + "sqzzHVQgJWNygbFhRKH/toUtvJp5Pcl1gwWCIBkYOWHZ052LXmHhAcMO7NEaaUP8\n"
                + "RzC/NDMC6bQ/R4bbYdHP7H795gmiK2wdE0Nc/F3LgXkOypkh6ZRjjghiy90hHrAD\n"
                + "OZqBfCZCK//Qofir9aNVrj31VOWm4nLeeOXr3xMv8QF5p06eYB+EalbdwRS9UbD0\n"
                + "8hOb6h4p6SOMj5V3f+zzZIh+0DG7VN/35EaFpVcRn+KNpJ1PYLjIEpEyAY1eE10o\n"
                + "q1vkMolCa8/Tvp/Fc29uubwj/Bi6pNlIXdYp8fqCLOo4WtCrGbC/oMDKCB7V5IZl\n"
                + "1+PZe1HPcZKiCTcgk3q81vpEAAN+8jvgAH3HetFmMoeH0oXmqHzKq6nB6pHhOwiM\n"
                + "GgIwfM7sjyj6nD3XJdg0+il/fqOxxHIlNfmmGF8QZ4QS0DS8IpPMC7RnoxfeFBm0\n"
                + "OjcUzCtFi3xN5EFNE2Xw4BvNb8qLrkbktLWbKw5D81szMKO7n4n5WTIlri2yNK+/\n"
                + "wUTxLTf0Dyz9mHxcUcrOFrQpbs5xwOh4GoyKsGwNzJA1mFOxOsxJuCqJJq1rOpGY\n"
                + "Pk5x0wJYZLKy16DmRekLEqE8kCc29rbMT/dms1a66G3eHn1r3Cp4oms92jJpj+63\n"
                + "aHitoOiBoX7M2/pKyW43obgn/PBQ+O0BZvU7O6a7nXH3D7CwUveaxwhsRsXBgFW3\n"
                + "hR6vj1UBc5bSFqy2F75UlwBR2xMgBiy+3sPWWa1FGxonWRtLHU+XIoGR6vN/H5qd\n"
                + "pwI86Ietps8A55st/+igauMudJHQSLSiQfh7Sx9jGRqr834ZaQX+5iM6AGe3QigB\n"
                + "rtNO+5UFWp4iG97oKoS+OsvG1PhETgd2wyP4HCwelw889ugWpLV7B/QZVizqjOiV\n"
                + "sHD8z+QtAN1KybBD/SBqzv9Fv9zc0OGzWx7RgHJJCVnTNWObih6/DxrrPHeltN3z\n"
                + "q1qpBsImPrbsBdnsfgF4rLYoagzytgUy5R3Iuy6oVJx/bbaS8Yq80N50/gBpduih\n"
                + "gqxLAFsnp2rtOfS7As3yfe0p3i8UWZm6xNdLKbNYqZcXKZ1JdON/yH44wHVPu/9L\n"
                + "2YrN7cDNqo3ufJvUYtm27JHjIhiN4g/HIpfpVviao7+b1wS/lsi8sLsl0hW/kyWe\n"
                + "nxTqKWUVgo/W0MyQnDGIRAHo1B0/YBAqF7cP3ZPboigu2GYVIL5Sipntu1YyEWQI\n"
                + "D05uaE+PPL0q+6NJ8bNYMI05+OphBvOcrDj7YomNeCsKdRyJCBBuNW7/y0pJ+MYp\n"
                + "XAQgdnB26UHJfwxX2nwK7LJPUmXnoF6AOLh/ciTq5ubsp9CtfZcPFCbc1sFbUjJk\n"
                + "-----END RSA PRIVATE KEY-----\n"
                ;

        PEMFile pf = new PEMFile(new StringReader(pem));
        pf.setPasswordProvider(new MyPasswordProvider(new String[] { "secret", "changeit" }));

        PEMFile.Entry entry = pf.getNext();

        assertNotNull(entry);
        assertEquals(PEMFile.PrivateKeyEntry.class, entry.getClass());

        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof RSAPrivateKey);

        RSAPrivateKey rpk = (RSAPrivateKey)pk;

        assertEquals(4096, rpk.getModulus().bitLength());
    }

    @Test
    public void testRSAEncryptedPrivateKeyNoPassword() throws Exception {
        String pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "Proc-Type: 4,ENCRYPTED\n"
                + "DEK-Info: DES-EDE3-CBC,079F3858FC92E561\n"
                + "\n"
                + "zDD1HQoJEFcbS0RUoB8H0GEDyK07b3UDzf89ylnTLmRvoOS7du6eyAqsGxYJnkmr\n"
                + "+xsTAMxpyyQRMSOo58tZz+aqebDtFUjvyI3R7P0ZosIGs2GDS5qVbch+PiqpnbXi\n"
                + "y3GDG92j75qePGl6/NFWky0QrZ61W3ev+9gqnwUENHBR65PlH5qwhBNta8N0d9LU\n"
                + "iaxieBL7TILrslQiIlsAxPOJ+I/2ZljtsMaHwjmBL48zFooNtk7kPQkUSVSTDJ9A\n"
                + "+pJMbWjoc9otWFK/X1qpNf00s7/FlEVpLCqZKiAYcNgIky3ZNRnEUd4YKYBefCrl\n"
                + "7MWgb2epOOuP5DfTcJUr7TQH62GTEzoec+RH8KWW3HfZvwXeuxx6n7DiARx1SfUx\n"
                + "d+qChYWWwsQMOZGG5Upt3bG4lPZPrPya+7bIkoMrkYNY8GjvfInbL+66pMRyw1Db\n"
                + "AUXGbyR1Ov7uTI3fHsQw1EgV0mooTrFY2njPBpmrKYW/fxSuCZLAFE8wX2yGnnrX\n"
                + "8CXbolBE44jviH22nHsN5NodDPEtJfxmFG/0mmDhNhfeQhL2aAPYGezJmvrUQ8L6\n"
                + "GX15FYBhrvBgsakqaq2EkW1jTseNC++TW5KuRJln8vKcFMlwM2WTxddRq+cpJoOZ\n"
                + "pX63Sbp90eO9pXaKGEmIzGlM6l1FTVWKIpmyTG3Y6Uyx4qoFhoLQ2fLcKuq58PSq\n"
                + "0f5a0mRm4rhuuXKQVHJiQQEOIOtnS+9oUPuzXbKACfRmva3WZ44tByOb3tY2iwrY\n"
                + "PsJ7Ur3fhwLOxMtSVuitLF/4BVMcmorgWhRCpJqTcHFjxECYhnF8jMOYAlzQOQg2\n"
                + "raKZWbAXTG6NPUEqAVlJRFP4BacZKNiUbWP3dEKHDNIuoDCAGqdO5MU5jSy9x0e/\n"
                + "CPgDpNU9xw2JnmTT4VGZmn0xpfO8b8sim5y0vf/TQ6Z77/NNa3pJn+42jtbs+syS\n"
                + "5Z/Du1zKXTXhX2fYQc/6/lWIdXhjfJrOMK+siRPFJxdL1TdwfoLJMh3IbD/neEd9\n"
                + "KuiMM1D9PgqAqe12L3TDdF2JWzQ5gjxsTyMJzUrhXnAH0xKjll6Nck50uUnZh0n7\n"
                + "MHHM8kyWoLN3JUhjQauh8VeJVk+SLnhPXggclU4WKf+znLSWapWYO4z+ZH3px1sr\n"
                + "tyjFXxWPbMB9ZjS9WkSxJe/dQeAC4DDXKtzTLa/pbsw6g0AJAaQmYFFcasChgOoL\n"
                + "vKRjxE4IHAaotHDbKKGyhDDfeEOoBACrXO0iprR7YmSYC1+CqcUmgvVVlEcQTVxh\n"
                + "bXA/aozGuSaLc3HJzm31D+ww2u/fmxHTZqjIDJBS2ZFx+gNHo/KNfB/1aoODrsu8\n"
                + "lWIVJVv36sMyI8oYH2u4XahOeOu+aE9bcalKT09rTF+f84R6g4pib7lQc4Zf1mIY\n"
                + "CPmk7d/bDXNYsVIfKojFuGNCQf0NX2v2Bj/SVPBHOoAhHFKTn2ButTkUySh7ggZr\n"
                + "Jg4f3110E4AKpaXjdV0cBgluUvM3GVj1mc8lFe22wqdlpzgV9rRjn+US5VCydSe4\n"
                + "QWUmaxn8QCnIQrWmusCmE4XantCcYRE9f6YY4oYwMYQpqjYuIhxPkeItwv1wf6ll\n"
                + "yUtAmZ1zFQjzIAyD9oiPSMl7XxzR0baWAb2mGnZ68rStfatQFa7YwUFJW0Zf/0D8\n"
                + "dLBVYzf17wopfJNIHqOtt6OcRGK5+OMWQQJwh07DDeW2gPHiEjkFymSfv6yZesyN\n"
                + "/tQaTGyJC9Sxu6aUevWmrYwampseq7RA+CZxcleAWoQaO9c6UahcZmYUruQOq2ZO\n"
                + "sqzzHVQgJWNygbFhRKH/toUtvJp5Pcl1gwWCIBkYOWHZ052LXmHhAcMO7NEaaUP8\n"
                + "RzC/NDMC6bQ/R4bbYdHP7H795gmiK2wdE0Nc/F3LgXkOypkh6ZRjjghiy90hHrAD\n"
                + "OZqBfCZCK//Qofir9aNVrj31VOWm4nLeeOXr3xMv8QF5p06eYB+EalbdwRS9UbD0\n"
                + "8hOb6h4p6SOMj5V3f+zzZIh+0DG7VN/35EaFpVcRn+KNpJ1PYLjIEpEyAY1eE10o\n"
                + "q1vkMolCa8/Tvp/Fc29uubwj/Bi6pNlIXdYp8fqCLOo4WtCrGbC/oMDKCB7V5IZl\n"
                + "1+PZe1HPcZKiCTcgk3q81vpEAAN+8jvgAH3HetFmMoeH0oXmqHzKq6nB6pHhOwiM\n"
                + "GgIwfM7sjyj6nD3XJdg0+il/fqOxxHIlNfmmGF8QZ4QS0DS8IpPMC7RnoxfeFBm0\n"
                + "OjcUzCtFi3xN5EFNE2Xw4BvNb8qLrkbktLWbKw5D81szMKO7n4n5WTIlri2yNK+/\n"
                + "wUTxLTf0Dyz9mHxcUcrOFrQpbs5xwOh4GoyKsGwNzJA1mFOxOsxJuCqJJq1rOpGY\n"
                + "Pk5x0wJYZLKy16DmRekLEqE8kCc29rbMT/dms1a66G3eHn1r3Cp4oms92jJpj+63\n"
                + "aHitoOiBoX7M2/pKyW43obgn/PBQ+O0BZvU7O6a7nXH3D7CwUveaxwhsRsXBgFW3\n"
                + "hR6vj1UBc5bSFqy2F75UlwBR2xMgBiy+3sPWWa1FGxonWRtLHU+XIoGR6vN/H5qd\n"
                + "pwI86Ietps8A55st/+igauMudJHQSLSiQfh7Sx9jGRqr834ZaQX+5iM6AGe3QigB\n"
                + "rtNO+5UFWp4iG97oKoS+OsvG1PhETgd2wyP4HCwelw889ugWpLV7B/QZVizqjOiV\n"
                + "sHD8z+QtAN1KybBD/SBqzv9Fv9zc0OGzWx7RgHJJCVnTNWObih6/DxrrPHeltN3z\n"
                + "q1qpBsImPrbsBdnsfgF4rLYoagzytgUy5R3Iuy6oVJx/bbaS8Yq80N50/gBpduih\n"
                + "gqxLAFsnp2rtOfS7As3yfe0p3i8UWZm6xNdLKbNYqZcXKZ1JdON/yH44wHVPu/9L\n"
                + "2YrN7cDNqo3ufJvUYtm27JHjIhiN4g/HIpfpVviao7+b1wS/lsi8sLsl0hW/kyWe\n"
                + "nxTqKWUVgo/W0MyQnDGIRAHo1B0/YBAqF7cP3ZPboigu2GYVIL5Sipntu1YyEWQI\n"
                + "D05uaE+PPL0q+6NJ8bNYMI05+OphBvOcrDj7YomNeCsKdRyJCBBuNW7/y0pJ+MYp\n"
                + "XAQgdnB26UHJfwxX2nwK7LJPUmXnoF6AOLh/ciTq5ubsp9CtfZcPFCbc1sFbUjJk\n"
                + "-----END RSA PRIVATE KEY-----\n"
                ;

        PEMFile pf = new PEMFile(new StringReader(pem));

        PEMFile.Entry entry = pf.getNext();

        assertNotNull(entry);
        assertEquals(PEMFile.EncryptedPrivateKeyEntry.class, entry.getClass());

        // Nothing else to do, here
    }

    @Test
    public void testPKCS8RSAPrivateKey() throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDigM0A0cy3O/M7\n"
                + "NyYFbwrD0wvug+YviYl1/7gBLHCJA59pPLD7FFENbAsAcbfEkPFUdM0Y/yhNL5gY\n"
                + "s5YtZw57qPOWYE6m4WXvrqpVaz9Ozxv0C/JgEsgKczQ8m38cMdd2oqm22oHn/q52\n"
                + "oD9L0Xnq8Xx7jUR7Mbt+yYDCCy0z1Rf8PwJ7g0iQMGMnTZ+uzHd0NQdyM205Bbaq\n"
                + "pBP1BEMpCNplBtrgnaigoc6KoBM6V2cX7UAqBb8t8CkuZ+9+sGCCGMHscQXheOU1\n"
                + "dGvBPXc5tM3CLLmVawpZ8P7dwrQxkNusY820EC9QFsDNHTmI8kSFS7uijGGIZiJC\n"
                + "vzWHOgaP+fEFK2o+MKlJziOrenoj76O6IxtfIc2lWUTP5D8uQEIJcKU3dAMtgBoD\n"
                + "uGzqXtEA/j6d6sTbk5Ht57YBxpMgMBPGuwqmBN/L+oc9kH/a5bouobEvJBuVQZAf\n"
                + "R/HbrYpi1RK7qGA47iGfpx/OX75mEySps75mNt6QuKSs+JSxdMklRtBI4DyavH1O\n"
                + "7twGsz1S1INCIRi8AimSOydmgBtkJ9P85gcgrEyjbjFk/xLGCxt7KWmxRWP54Nad\n"
                + "z6MxTWvy1mK5l9ZcmOlOa/3krYVAhvtL5UMln9+3hdk/I60TDbJchUETGD7XpTsD\n"
                + "TxOYa6zHAfv/aNAHVsMjpm2C+05DfQIDAQABAoICAQDP79jD6NccXIAWm7FfCasD\n"
                + "TYvFovc+KvC0EFfXU/nX/yhoj1wWlHc4cDjFZqCDZ2D13OixCwXvnkLuYmf7NIIa\n"
                + "SmedZLqv/3r6iAo9suCCtCYAbLtNMdDNryeEgGg39RXOBtTxVjYuSiPWKZUSQLPB\n"
                + "WYKjVnRI+MYdRlXbTjFoRTfozdu0kjiajqFoYp229mSvnUNBty6NS85/Z3Qe2pPh\n"
                + "Zww/9QQZcwNsvD8GCqC8TaMKVzcxnOb/AFx+CtLWJoviw2G8c6IndTpPUZre41PB\n"
                + "+Vdv7GlPX9435cPEyEtuuYLCBznAFZ+p0cmcRDkenPMEwBr4xhGAC+tmBW3ZwA5m\n"
                + "grKTdgL1caLOJLq0JSH0iAL1VLHq38dF0+QbayEEcvC0kU5yXPD6/0FrsGlXhzxl\n"
                + "VYJJjLl0prx+PYaXZr01Wq7ifmMexLT8cCJ2hNtitZQbK+8A023XSO0YdFQG6AEV\n"
                + "nxAlwQ+f6D7jV2vbciCuqpB5FD7HuXxhXmNNjsrL4/JFWLY9WCsXp9oxA0hdC2Pf\n"
                + "WixyE7ddtA5Z/0FJWbfqTOnMUZaJK5PRuYS8Bq4+oL7FECGj2skLeUxA3E9T96Cg\n"
                + "9M5l/sMmrCYPSKNHzqm6zBGhkRWNxhDhknMIUuH6mqLGR9BRFsWpIy1VGy8N0YyG\n"
                + "VL85EyuGhi6KonYAjXJWQQKCAQEA8y6JK+kV2TsDcA5dutActlfrCI6j2a6auLrl\n"
                + "13vcMcEIicsVljdQo4nlRvlw9T27tVkJteBjz2okOlWh2+DMqYs80IkHNmfo+0+T\n"
                + "c7T7AoL7FgOuqu8SeMF3Rhf617A8tw5QZsDQ7xvo6233kSePuF2Kf62FqkcGYMOv\n"
                + "8U9+C9PNUYDLDGdoGY3ZBalsgMDRO8A7TEs9DE6Q6Blx04cdltFfHnos8lDC+YKl\n"
                + "HqCrKifSuugL4kBbp3f+kA/mjKA/QX9hreQyQDc9E7czzvJIvHgE/BT4zbg+p40J\n"
                + "R1qiPfqOWC30D24yIAZyYhezZ9+IaBiBeY0SfUODVeDoGVIucQKCAQEA7nE0kUTz\n"
                + "v2Qqf90xqqcZFQDhwTPx7fZQjXFWFRnROIIe067zNprBpmqwL1mc40n0hYtfmAqo\n"
                + "p6wMm5dnik991UZUqfs+XTx4QaEd5bDqt3MovOK7hITe5rFIWpLWG8P5PmcdGaml\n"
                + "6A8j6yUsvG/d8cTY1Oq/n4WX9LWz7pPGPLgD+UuAB6GCXKtnKltKioJZcllOhth5\n"
                + "6YUl8+3miOz7q9iK0D+Urs92UHIEHbl+VZZTejnSgU6pAkx7g0M2XiVjsVkXiAJA\n"
                + "aD13k29NelmwnFCX6NtCWTD1P4M4NJpPKReIsKK8OJLmHZuRsZRnwkUBW7Z1SFhf\n"
                + "fArNfD/Qyo/DzQKCAQBQlFb3qeCHfrqA4wHD6TnaYf+LclhwxR6Xn7aRVIV+JwyB\n"
                + "PD4G7IVX61WB0x3O5YnRaZOCJLxt+inO+pkLls26UFzybLVrHbthqtidOpcCGgzB\n"
                + "Gq9CDL3+LX0sSL3hwpAbyC50Hegdkw33FRU3j/hbiwNdk037QlWmsrEWMNT/bktW\n"
                + "emrNzWX9Mbd73MwLTdkHB4eenD+6WD5D6kqBYQA4/V+bZbiHAqPYsaWtJGgTK+bz\n"
                + "7/ggHFtCfsxnSB2I84CCX4cqa7cK+ELQyZ/tLvNTICHmtbxLzoVUV7N/ZVTlXKTW\n"
                + "K0P36PfLDNfSETBtdvBoLdaZRFmgEELwrfm6ijTBAoIBAQC93hM34ioeK0rUSnR0\n"
                + "KV8FpJAf4pcxH8SA/NDJOKerUaHueg9dWdn+BFKLQdZ1/rvhY1wZm9M0wQHBG8zt\n"
                + "C+NtYvWj7VZ5s98mk39VGY2tytuTnRAotA0ysdSlmus3bNQZ5s37U2Wy5et6IT4A\n"
                + "Ryv6iv8GfG9ePWkFCXNf9PgT/YvchUxLx0YhOLOLvOocZTOIpKitI8/gLZBNLxE1\n"
                + "00+MRYAz140zrivOXxv792ssB+otF8ISCWr3U6O+oFS4nxlFbWYZfYGAAAIpuqV9\n"
                + "WdIShvKQD5hDoYKIspqc+Is0c3L7BHrQqdjnlqtrNntw7LXqK940X3qZMZjy6XX+\n"
                + "9n+5AoIBAEgwTLNAFv/Sq8tCE0IYtGwW+yUyfnMauuZruoYZEV1XWTfaeXJfyBkj\n"
                + "NH9dtd2UOFE3D5eoHjssVjwGjSP7G4WDRM+XKzV3kHfG6o0YzMrwWflxW+o/EiX4\n"
                + "Tqx0FEztyfKXd+zgFwL31J9EZ6hLQAB8f4m3DrUrMOi5NrdCT/z2HghU7tMUzShI\n"
                + "rNPSSP21tG71oMEbrekawsyUuI8huf3XMo9qFTS+pSiGR9C6quiKpWyiV58SuoNf\n"
                + "Xih6H4n4zJsVWPrdKgsS4viEGmZPt1T5T6Ru40LFCpvRs37K1iZTsyDAbyfqHQ3p\n"
                + "OfO+Ekm6BmdNEDiQ3w1H18pOMQsFFvo=\n"
                + "-----END PRIVATE KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PrivateKeyEntry);
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof RSAPrivateKey);

        RSAPrivateKey rpk = (RSAPrivateKey)pk;

        assertEquals(4096, rpk.getModulus().bitLength());
    }

    @Test
    public void testPKCS8DSAPrivateKey() throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + "MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQDwtMSTHXOrGK7fswcij7WuAkem\n"
                + "vlfBZz3cgDdlxWKX0+n20MtcF+z+rJgnYmYw3m4ibO49orBL3fCrP/pXm0PF7hXv\n"
                + "Mu3x564+Ehd4INC7LNjkNKNSlfzRk7OAoa+U/RS8jSN+jk5Lx6MmeL1V9e014Vgu\n"
                + "uhpSRCX3NQwICqvRuBiffUYuJv1wLjZdI8zcXvZEUiP0OppTPfdXWLDOUr3G98ib\n"
                + "rfFfnFkrImcXsyvnqBgd18KDpKg8wEyevF0SQHXIozxlwUFLuo/l3sHHu22MPdVB\n"
                + "wv3eBu/uJG23qPQVafccC5plPLXH6uOiJRzmSbjxqpBoT863Y+CYpqAi5gQjAiEA\n"
                + "qDUUVxzOzNW3vrAPtcX9juenAqFQfdolIyzjlSzc8/UCggEAZ/Wwh0Tyl+dxcuwf\n"
                + "9FA9bYcogdKztUzfMPud1V2JrkDnILUaLgfF4rvADGF2K9X6Mj7WfzE7bC0tgg7M\n"
                + "IWF7hz+M6dFItGhaWaQaxuHSYDcTbCShDis5d33jKY3FCfXLCrgu2+njJuClip9B\n"
                + "p24qHg4uPUQYlElqx6gNoOWCyhgwga16nNB6hMiqZATOwJW2bji4lO1n3EkqxzYm\n"
                + "skTWQpCwRIfMQ/gNBXsLSszAFhDZhDsc8J2rWO6CjnpnJsggSxavR6WBVMRCSJkZ\n"
                + "2muefJQUp39eO0pHCugXl+K0MyEy0XDoO8ly/jsJcvG+Dbh3vX0vGOR+0BD5QDxC\n"
                + "yeWyewQiAiApXOYDQX328dlAmPsF+RAphH89AophcKVARwMmUE2Nmg==\n"
                + "-----END PRIVATE KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PrivateKeyEntry);
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof DSAPrivateKey);

        DSAPrivateKey dpk = (DSAPrivateKey)pk;

        assertEquals(2048, dpk.getParams().getP().bitLength());
    }

    private static int roundBitsToByteBits(int b) {
        if(0 == (b & 0x7)) {
            return b;
        } else {
            return (b + 8) & 0xfff8; // Round up to the nearest 8
        }
    }

    @Test
    public void testPKCS8EncryptedRSAPrivateKey() throws Exception {
        String pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + "MIIJaTAbBgkqhkiG9w0BBQMwDgQIaYx28Px5ZqgCAggABIIJSAd5xOKH35wgOcSD\n"
                + "4tFzp58haa5KSFjeknJ55QsDOUvzryg4JqNAeozjr6rPNnOLVPtwuD/FrhdsEMtu\n"
                + "XbD/qJjBH8oJervxrTuSSkbwIVXcT9g8VtygoT6VHC+mXeSCN4SNy6ovfP78eepz\n"
                + "Pn0dsfA5VZ95+pYqfr9z5lYUbVFhHsB2pnJZp4gC9qJwbXuNA6BYuNey3f4SNQz4\n"
                + "GMU3q0nPnDH6+XWAGL8y8h08fSG0hktV7i+uhGM8hau83Bk7bvZq3xCJVr6T/Gvg\n"
                + "FLv2wbl4rCw6ZGwRcgBau3RZ/QuZGv3JMwS3Q79Z14yuavV7yp+fvdlX0/zjhNA5\n"
                + "kAzOrmARzZpYprso02c6coRYjcP9uRx5137xaK3E7G1T9HQQDdfWn8bAdDTuR205\n"
                + "JvMG9AbybHLt/YsztLaIRjuKhZogzUum9y7fOO4G7VdMCnamB0Afchx3fYaylo21\n"
                + "qQ7KTDDtohPoYBhO6hUtswndCoHffMwgNcaOrFzLv+NXQS7+uWuPGWIeRUq+ok6E\n"
                + "ZOvMm0DDrPCAGB2qazwTQl5EQfy/XkEOpnjQviDabbWvLTgJXctFDqBEVuv2i7ky\n"
                + "xOW13/uDxO5UmJz6HbwtQON8bawKcKKEWlMehKopAUuSFovovaMnLOvAdK1CIbyO\n"
                + "YwiozLDh22mmfdvKLCFIiQyGVL8MK0tnSwwIt/wuVjNdSUefAFUWpr0bS2iqsPat\n"
                + "fHskf4sWRNTllYTppuEW9w02IIpmApht6XVHcYp6+rfPyKEUZ7P6jpLIbAjtMzvQ\n"
                + "LIAz23zD4rAH94O+KMws1ZKApKV202suyZC42LMqt4v+c092Fs4OkK++AEO9pfnb\n"
                + "X5QGOEUlCtqfPAnpSG+QVDjv0RQvxu/QfNcRbzcz2tiEbg48/Z3iDbr9v2V+pAe7\n"
                + "BbvviJE9VBYw5JJScTV1AyXqNJqEw+MtIzHXtj9bCtb8lH9M320SsZsbvU84AUs4\n"
                + "xhYQLMTW3fcNzJpMbwPsCh97TJ6VfJUzedjuPDWkiXvKznLLNS/a1Ar+h2qcjXXC\n"
                + "TI2DZpe9quQ196CoycckkdtB0jjSagNytnmd9kjCBEtBzdW77+9u2cPUrYwwI6hg\n"
                + "4YeOmblzce2Tuqe5U2ctv17FvWz7Fmt1ji88wyqpDBd1TCnWmj/hwI2y9rqLrZ9a\n"
                + "y6//KGSYfhLf6Ntw/WxTVF/96F7J2TVFRo/6s+9DhzAxCxuA8V9ngroakCUpZwRN\n"
                + "8XPBouI4oI59qTwPW+/8B/xwnqwx/uqH9qpAjvtZyjCsMyyl+1yrt2zVPPFgnnLH\n"
                + "i4aE24Der2zkv7htA8ykCWJw+4fqo0mAIq1hN+cfUv2JnWBn3vCpEkI8PHkgoSsB\n"
                + "Gdy21HuOka23zpZKZ4J5tzV0camvYjP2PgeW8ikujzDgru8Jab9/pwu+46R/uDLX\n"
                + "PdyrcVCBssrouryIesfhd4m6UXWv0Lw+yRGCxrVOf92SwqD510OloJwLwQDNGIAO\n"
                + "VL1Fu1sEWW9mXzZoskENrpqOqq0+KogY/JgzLT02Nmxfgl9rIHjqN7FtIHjapCyO\n"
                + "EXwNQ8/CsdftNKbBZ7PnHJs7P/sYuOs6oYI3jyg79cVlFvnV67jVAfrN3darhoe0\n"
                + "UCE05+YcDgWDibNBW2qm/CpbbMUsqdb2tIyj0d3e5SLE4Nb5q7gMGw/8h01zrU+Z\n"
                + "utAhyUfWnYnH3nSA7zaeAhQ/Mi26zKcUdrasBkT4JcXRPBU+c2XyREIQLxB6rcIl\n"
                + "Qihwwi/OiOrdzhdHmBJcIsMG5QS2ubUXwkmwyYVTkm+YrNtn1ZH6w5Jb0Zhd2ONo\n"
                + "6bpEaKl5bq+Dsg7w/eC2EF+UwMY9ah/Qx5zEP9Utq+dk6YmdjADQX6IVVmhMvMM2\n"
                + "ns/+TGb7ExOa2Qm1UNaH79SZa9sbeKNNJsVhOFf01YHgfyZE4NOla/VuM/uIKAZo\n"
                + "rb/y+5g2lRKcOunUg9tj72ilxrxdP+XtcqrLk4HnnsNnQoDxr2h3FOcwjS1YIyRw\n"
                + "FsfsG8gU7r246d/aoSkbmgD4r1bAgDETuIujD6rS9gETHhCq2MwrCEFz8Sp0OKgz\n"
                + "qie+ovpHZKmqkcxu3yIZ8jxcAKnOXpT5DwGF1cRYH3EbSyO61IP5sS6kO3/n2Upr\n"
                + "SgLTA9cGYdpB0CpiDfkX1T83+tG5FkusXFP489butCjMG9+exEykJkAtw3zfNMVf\n"
                + "TZ5xOqzZkeTjX6a+kJ4st1XD7sgkjp9jKWywM342R2xbAD8FhuDiv8o74aPo1nt8\n"
                + "QdqU5PJPuvs2SqzCL7GqwUMBU8I18GCFdXijdgk33UmHw9eTLXtS/BfXtYPsGhFy\n"
                + "BoSfU7xCz060T6F+Wui3gBl21PcvVARBLBOaHoUTTNoKT0RV0vJX71UoDfa9Vpn+\n"
                + "TSFfIEJu5TFIZ5RO+CdXt9GKUBQhTaCZl85I6tS0NjEY/eejzacOP33izoDw0BIv\n"
                + "OJUfvnUcfHMqxdgG+UTCAS3Ytf4A0e7Bcd1Pkyksd4xfRsMRqEvPR97fa+6hpVrD\n"
                + "40L0N04IpdcMKP3nI9YTizyGfkKPaDYz1WdFBjqkR5MdMTP4AVCJRRJhCkfKyxwq\n"
                + "fBHzLz3mlCNf7095EkYlWdKSv/RI2P/vuFOc9jdc5lUc/m3fKC5XwTzWzDHuMkYx\n"
                + "vW+10IHQxUA25E9ZuAnZvQLiwEdBzMeZzfOcGNhgr21LawxBdByGU7MevyST4m0t\n"
                + "oSiMQ0QSMWU3E3rqt8/b6OpNjNlXn08YWNnZdcrL7oKJh/fXlmEoTYni6unQF7aY\n"
                + "/JSuSAFzIRdJcXAMMGvzOF99a4bfPrH7wXVozSBgEcXZIHoZjyKOHEjrZYXGCRZw\n"
                + "8kzg6LBvvoi7u+VmcGDYFV60OoOEtBvZ1MMHxdXViApVeWAiIeVSLnfn7duGwpZt\n"
                + "Vdi30pirXiIiyuxpyGdA9QmFX1RgdENHwqT5BwyvWgr9rtKi8gpYMwdoe+mCcNyp\n"
                + "TLS8Qkc08kYnQf/sXi6dieH7TwnOtG2JRHuHDRgGz4UNiUSsHjO+LnSaKVWsFYQ9\n"
                + "3mzphALdp8p9yqda4S0SRr9/0CeKQZhlRKUmvxRtozyeirW+ajKsfTsGMOiat+l/\n"
                + "HEzeZYydKK59wGZ8qjCLIA3xquRFMhAKxl/Tt+eNjRInGS3UTxmV2gS5XI9vjh4b\n"
                + "6rf7F0K9fUZxYRvg/w==\n"
                + "-----END ENCRYPTED PRIVATE KEY-----\n"
                ;

        PEMFile pf = new PEMFile(new StringReader(pem));
        pf.setPasswordProvider(new MyPasswordProvider(new String[] { "secret", "changeit" }));

        PEMFile.Entry entry = pf.getNext();
        assertNotNull(entry);
        assertEquals(PEMFile.PrivateKeyEntry.class, entry.getClass());
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof RSAPrivateKey);

        RSAPrivateKey rpk = (RSAPrivateKey)pk;

        assertEquals(4096, rpk.getModulus().bitLength());

        assertNull(pf.getNext());
    }

    @Test
    public void testPKCS8EncryptedRSAPrivateKeyNoPassword() throws Exception {
        String pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + "MIIJaTAbBgkqhkiG9w0BBQMwDgQIaYx28Px5ZqgCAggABIIJSAd5xOKH35wgOcSD\n"
                + "4tFzp58haa5KSFjeknJ55QsDOUvzryg4JqNAeozjr6rPNnOLVPtwuD/FrhdsEMtu\n"
                + "XbD/qJjBH8oJervxrTuSSkbwIVXcT9g8VtygoT6VHC+mXeSCN4SNy6ovfP78eepz\n"
                + "Pn0dsfA5VZ95+pYqfr9z5lYUbVFhHsB2pnJZp4gC9qJwbXuNA6BYuNey3f4SNQz4\n"
                + "GMU3q0nPnDH6+XWAGL8y8h08fSG0hktV7i+uhGM8hau83Bk7bvZq3xCJVr6T/Gvg\n"
                + "FLv2wbl4rCw6ZGwRcgBau3RZ/QuZGv3JMwS3Q79Z14yuavV7yp+fvdlX0/zjhNA5\n"
                + "kAzOrmARzZpYprso02c6coRYjcP9uRx5137xaK3E7G1T9HQQDdfWn8bAdDTuR205\n"
                + "JvMG9AbybHLt/YsztLaIRjuKhZogzUum9y7fOO4G7VdMCnamB0Afchx3fYaylo21\n"
                + "qQ7KTDDtohPoYBhO6hUtswndCoHffMwgNcaOrFzLv+NXQS7+uWuPGWIeRUq+ok6E\n"
                + "ZOvMm0DDrPCAGB2qazwTQl5EQfy/XkEOpnjQviDabbWvLTgJXctFDqBEVuv2i7ky\n"
                + "xOW13/uDxO5UmJz6HbwtQON8bawKcKKEWlMehKopAUuSFovovaMnLOvAdK1CIbyO\n"
                + "YwiozLDh22mmfdvKLCFIiQyGVL8MK0tnSwwIt/wuVjNdSUefAFUWpr0bS2iqsPat\n"
                + "fHskf4sWRNTllYTppuEW9w02IIpmApht6XVHcYp6+rfPyKEUZ7P6jpLIbAjtMzvQ\n"
                + "LIAz23zD4rAH94O+KMws1ZKApKV202suyZC42LMqt4v+c092Fs4OkK++AEO9pfnb\n"
                + "X5QGOEUlCtqfPAnpSG+QVDjv0RQvxu/QfNcRbzcz2tiEbg48/Z3iDbr9v2V+pAe7\n"
                + "BbvviJE9VBYw5JJScTV1AyXqNJqEw+MtIzHXtj9bCtb8lH9M320SsZsbvU84AUs4\n"
                + "xhYQLMTW3fcNzJpMbwPsCh97TJ6VfJUzedjuPDWkiXvKznLLNS/a1Ar+h2qcjXXC\n"
                + "TI2DZpe9quQ196CoycckkdtB0jjSagNytnmd9kjCBEtBzdW77+9u2cPUrYwwI6hg\n"
                + "4YeOmblzce2Tuqe5U2ctv17FvWz7Fmt1ji88wyqpDBd1TCnWmj/hwI2y9rqLrZ9a\n"
                + "y6//KGSYfhLf6Ntw/WxTVF/96F7J2TVFRo/6s+9DhzAxCxuA8V9ngroakCUpZwRN\n"
                + "8XPBouI4oI59qTwPW+/8B/xwnqwx/uqH9qpAjvtZyjCsMyyl+1yrt2zVPPFgnnLH\n"
                + "i4aE24Der2zkv7htA8ykCWJw+4fqo0mAIq1hN+cfUv2JnWBn3vCpEkI8PHkgoSsB\n"
                + "Gdy21HuOka23zpZKZ4J5tzV0camvYjP2PgeW8ikujzDgru8Jab9/pwu+46R/uDLX\n"
                + "PdyrcVCBssrouryIesfhd4m6UXWv0Lw+yRGCxrVOf92SwqD510OloJwLwQDNGIAO\n"
                + "VL1Fu1sEWW9mXzZoskENrpqOqq0+KogY/JgzLT02Nmxfgl9rIHjqN7FtIHjapCyO\n"
                + "EXwNQ8/CsdftNKbBZ7PnHJs7P/sYuOs6oYI3jyg79cVlFvnV67jVAfrN3darhoe0\n"
                + "UCE05+YcDgWDibNBW2qm/CpbbMUsqdb2tIyj0d3e5SLE4Nb5q7gMGw/8h01zrU+Z\n"
                + "utAhyUfWnYnH3nSA7zaeAhQ/Mi26zKcUdrasBkT4JcXRPBU+c2XyREIQLxB6rcIl\n"
                + "Qihwwi/OiOrdzhdHmBJcIsMG5QS2ubUXwkmwyYVTkm+YrNtn1ZH6w5Jb0Zhd2ONo\n"
                + "6bpEaKl5bq+Dsg7w/eC2EF+UwMY9ah/Qx5zEP9Utq+dk6YmdjADQX6IVVmhMvMM2\n"
                + "ns/+TGb7ExOa2Qm1UNaH79SZa9sbeKNNJsVhOFf01YHgfyZE4NOla/VuM/uIKAZo\n"
                + "rb/y+5g2lRKcOunUg9tj72ilxrxdP+XtcqrLk4HnnsNnQoDxr2h3FOcwjS1YIyRw\n"
                + "FsfsG8gU7r246d/aoSkbmgD4r1bAgDETuIujD6rS9gETHhCq2MwrCEFz8Sp0OKgz\n"
                + "qie+ovpHZKmqkcxu3yIZ8jxcAKnOXpT5DwGF1cRYH3EbSyO61IP5sS6kO3/n2Upr\n"
                + "SgLTA9cGYdpB0CpiDfkX1T83+tG5FkusXFP489butCjMG9+exEykJkAtw3zfNMVf\n"
                + "TZ5xOqzZkeTjX6a+kJ4st1XD7sgkjp9jKWywM342R2xbAD8FhuDiv8o74aPo1nt8\n"
                + "QdqU5PJPuvs2SqzCL7GqwUMBU8I18GCFdXijdgk33UmHw9eTLXtS/BfXtYPsGhFy\n"
                + "BoSfU7xCz060T6F+Wui3gBl21PcvVARBLBOaHoUTTNoKT0RV0vJX71UoDfa9Vpn+\n"
                + "TSFfIEJu5TFIZ5RO+CdXt9GKUBQhTaCZl85I6tS0NjEY/eejzacOP33izoDw0BIv\n"
                + "OJUfvnUcfHMqxdgG+UTCAS3Ytf4A0e7Bcd1Pkyksd4xfRsMRqEvPR97fa+6hpVrD\n"
                + "40L0N04IpdcMKP3nI9YTizyGfkKPaDYz1WdFBjqkR5MdMTP4AVCJRRJhCkfKyxwq\n"
                + "fBHzLz3mlCNf7095EkYlWdKSv/RI2P/vuFOc9jdc5lUc/m3fKC5XwTzWzDHuMkYx\n"
                + "vW+10IHQxUA25E9ZuAnZvQLiwEdBzMeZzfOcGNhgr21LawxBdByGU7MevyST4m0t\n"
                + "oSiMQ0QSMWU3E3rqt8/b6OpNjNlXn08YWNnZdcrL7oKJh/fXlmEoTYni6unQF7aY\n"
                + "/JSuSAFzIRdJcXAMMGvzOF99a4bfPrH7wXVozSBgEcXZIHoZjyKOHEjrZYXGCRZw\n"
                + "8kzg6LBvvoi7u+VmcGDYFV60OoOEtBvZ1MMHxdXViApVeWAiIeVSLnfn7duGwpZt\n"
                + "Vdi30pirXiIiyuxpyGdA9QmFX1RgdENHwqT5BwyvWgr9rtKi8gpYMwdoe+mCcNyp\n"
                + "TLS8Qkc08kYnQf/sXi6dieH7TwnOtG2JRHuHDRgGz4UNiUSsHjO+LnSaKVWsFYQ9\n"
                + "3mzphALdp8p9yqda4S0SRr9/0CeKQZhlRKUmvxRtozyeirW+ajKsfTsGMOiat+l/\n"
                + "HEzeZYydKK59wGZ8qjCLIA3xquRFMhAKxl/Tt+eNjRInGS3UTxmV2gS5XI9vjh4b\n"
                + "6rf7F0K9fUZxYRvg/w==\n"
                + "-----END ENCRYPTED PRIVATE KEY-----\n"
                ;

        PEMFile pf = new PEMFile(new StringReader(pem));

        PEMFile.Entry entry = pf.getNext();
        assertNotNull(entry);
        assertEquals(PEMFile.EncryptedPrivateKeyEntry.class, entry.getClass());

        // Nothing else to do, here
    }

    @Test
    public void testPKCS8ECPrivateKey() throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGFE0WsmiY2G1ezcq\n"
                + "5wjKo7PJ//Uv6zZRohWnhjUfkk+hRANCAATQBpfc6JzP+MhVjScdJz3tgFqUD3rh\n"
                + "nlAF7jENooOYEcU4geELRIsQHTTmjh6/PctdH4BZRkgerISMsDKf++Dk\n"
                + "-----END PRIVATE KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PrivateKeyEntry);
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof ECPrivateKey);

        ECPrivateKey ecpk = (ECPrivateKey)pk;

        assertEquals(256, roundBitsToByteBits(ecpk.getS().bitLength()));
    }

    @Test
    public void testPKCS8EncryptedECPrivateKey() throws Exception {
        String pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + "MIGwMBsGCSqGSIb3DQEFAzAOBAhAtBH0o5JePAICCAAEgZBLW+bwqV/QTbEQhiZY\n"
                + "jYOit8Ly0ke9lx5ZRvYRNJWG0JkvDOPMkXp9LMgtmZWmCeZCZabDTmJY02CFXsyQ\n"
                + "BxGqym2bN68NvsJc7O65kcUr4z6RC+8OY7iLkFV9/2WEOMEh0CNrxPk83vh3nXo3\n"
                + "BJTbK0TQUVxxf1KmDUUk531N8wyJwUoysUeHSTIixT/YOaE=\n"
                + "-----END ENCRYPTED PRIVATE KEY-----\n"
                ;

        PEMFile pf = new PEMFile(new StringReader(pem));
        pf.setPasswordProvider(new PasswordProvider() {
            public String getPassword() {
                return "changeit";
            }
        });

        PEMFile.Entry entry = pf.getNext();

        assertNotNull(entry);
        assertEquals(PEMFile.PrivateKeyEntry.class, entry.getClass());
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof ECPrivateKey);

        ECPrivateKey ecpk = (ECPrivateKey)pk;

        assertEquals(256, roundBitsToByteBits(ecpk.getS().bitLength()));
    }

    @Test
    public void testCertificate() throws Exception {
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + "MIIBzjCCAXQCCQCGzKmQUWtUXjAKBggqhkjOPQQDBDBvMQswCQYDVQQGEwJVUzER\n"
                + "MA8GA1UECAwIVmlyZ2luaWExEjAQBgNVBAcMCUFybGluZ3RvbjEPMA0GA1UECgwG\n"
                + "Q0hBRElTMRQwEgYDVQQLDAtEZXZlbG9wbWVudDESMBAGA1UEAwwJbG9jYWxob3N0\n"
                + "MB4XDTIwMDkxMTEzMTkxN1oXDTIxMDkxMTEzMTkxN1owbzELMAkGA1UEBhMCVVMx\n"
                + "ETAPBgNVBAgMCFZpcmdpbmlhMRIwEAYDVQQHDAlBcmxpbmd0b24xDzANBgNVBAoM\n"
                + "BkNIQURJUzEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxEjAQBgNVBAMMCWxvY2FsaG9z\n"
                + "dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPqr8C3yiYsYgpJZaKdDUNQCLsMf\n"
                + "tq6PQCLCAebPDYYvujB4kg379AOgz1utoQD3h+t5pkWSJCwSn60Q+huy8AUwCgYI\n"
                + "KoZIzj0EAwQDSAAwRQIgWr0aF/tPatSxNiTRIqUu3d4NvuEg4ofCd8tGJQkFcG4C\n"
                + "IQDGXd4iLzpmvErENBeY27VH8AaP5ARhLlf+GNfpzpt6Sg==\n"
                + "-----END CERTIFICATE-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.CertificateEntry);
        PEMFile.CertificateEntry certEntry = (PEMFile.CertificateEntry)entry;

        Certificate cert = certEntry.getCertificate();

        assertTrue(cert instanceof X509Certificate);

        X509Certificate xc = (X509Certificate)cert;

        assertEquals(new BigInteger("9713324933637690462"), xc.getSerialNumber());
    }

    @Test
    public void testRSAPublicKey() throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4oDNANHMtzvzOzcmBW8K\n"
                + "w9ML7oPmL4mJdf+4ASxwiQOfaTyw+xRRDWwLAHG3xJDxVHTNGP8oTS+YGLOWLWcO\n"
                + "e6jzlmBOpuFl766qVWs/Ts8b9AvyYBLICnM0PJt/HDHXdqKpttqB5/6udqA/S9F5\n"
                + "6vF8e41EezG7fsmAwgstM9UX/D8Ce4NIkDBjJ02frsx3dDUHcjNtOQW2qqQT9QRD\n"
                + "KQjaZQba4J2ooKHOiqATOldnF+1AKgW/LfApLmfvfrBgghjB7HEF4XjlNXRrwT13\n"
                + "ObTNwiy5lWsKWfD+3cK0MZDbrGPNtBAvUBbAzR05iPJEhUu7ooxhiGYiQr81hzoG\n"
                + "j/nxBStqPjCpSc4jq3p6I++juiMbXyHNpVlEz+Q/LkBCCXClN3QDLYAaA7hs6l7R\n"
                + "AP4+nerE25OR7ee2AcaTIDATxrsKpgTfy/qHPZB/2uW6LqGxLyQblUGQH0fx262K\n"
                + "YtUSu6hgOO4hn6cfzl++ZhMkqbO+ZjbekLikrPiUsXTJJUbQSOA8mrx9Tu7cBrM9\n"
                + "UtSDQiEYvAIpkjsnZoAbZCfT/OYHIKxMo24xZP8SxgsbeylpsUVj+eDWnc+jMU1r\n"
                + "8tZiuZfWXJjpTmv95K2FQIb7S+VDJZ/ft4XZPyOtEw2yXIVBExg+16U7A08TmGus\n"
                + "xwH7/2jQB1bDI6ZtgvtOQ30CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PublicKeyEntry);
        PEMFile.PublicKeyEntry pubEntry = (PEMFile.PublicKeyEntry)entry;

        PublicKey pk = pubEntry.getPublicKey();

        assertEquals("RSA", pk.getAlgorithm());

        RSAPublicKey rpk = (RSAPublicKey)pk;
        assertEquals(4096, rpk.getModulus().bitLength());
    }

    @Test
    public void testDSAPublicKey() throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + "MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQDwtMSTHXOrGK7fswcij7WuAkemvlfB\n"
                + "Zz3cgDdlxWKX0+n20MtcF+z+rJgnYmYw3m4ibO49orBL3fCrP/pXm0PF7hXvMu3x\n"
                + "564+Ehd4INC7LNjkNKNSlfzRk7OAoa+U/RS8jSN+jk5Lx6MmeL1V9e014VguuhpS\n"
                + "RCX3NQwICqvRuBiffUYuJv1wLjZdI8zcXvZEUiP0OppTPfdXWLDOUr3G98ibrfFf\n"
                + "nFkrImcXsyvnqBgd18KDpKg8wEyevF0SQHXIozxlwUFLuo/l3sHHu22MPdVBwv3e\n"
                + "Bu/uJG23qPQVafccC5plPLXH6uOiJRzmSbjxqpBoT863Y+CYpqAi5gQjAiEAqDUU\n"
                + "VxzOzNW3vrAPtcX9juenAqFQfdolIyzjlSzc8/UCggEAZ/Wwh0Tyl+dxcuwf9FA9\n"
                + "bYcogdKztUzfMPud1V2JrkDnILUaLgfF4rvADGF2K9X6Mj7WfzE7bC0tgg7MIWF7\n"
                + "hz+M6dFItGhaWaQaxuHSYDcTbCShDis5d33jKY3FCfXLCrgu2+njJuClip9Bp24q\n"
                + "Hg4uPUQYlElqx6gNoOWCyhgwga16nNB6hMiqZATOwJW2bji4lO1n3EkqxzYmskTW\n"
                + "QpCwRIfMQ/gNBXsLSszAFhDZhDsc8J2rWO6CjnpnJsggSxavR6WBVMRCSJkZ2mue\n"
                + "fJQUp39eO0pHCugXl+K0MyEy0XDoO8ly/jsJcvG+Dbh3vX0vGOR+0BD5QDxCyeWy\n"
                + "ewOCAQUAAoIBABYUx79Wirat8TRGHaBGv+QHtsFUx7rWJYio6ptz0cgRJ3I4sxhF\n"
                + "C/SgccH42cxpQn13IcFAja+XIr7Jtuf9hlJhFJe9QSENfzYCsFh4r6MSqp7iPkKn\n"
                + "EBLN6XG9MWHDiTxfRji3mmcoLwpERzECaXXO9ttmIJxF1XA1N+77WxBrtrAvvLDB\n"
                + "o6u5/p8qsdBTYXpiYFymDmX56mhPD0dztlk0vI/eiFw6iGXMSiKrBKWL/nmkvQF4\n"
                + "p6maNvHg3uQb7092tfAvhdOqHUIN85i2aEgpKf6CS19L3ao3yHo5ZwYsNrNErI41\n"
                + "jAaLGu0S3O2nBBicvxoUmchrRggZee2yvxk=\n"
                + "-----END PUBLIC KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PublicKeyEntry);
        PEMFile.PublicKeyEntry pubEntry = (PEMFile.PublicKeyEntry)entry;

        PublicKey pk = pubEntry.getPublicKey();
        assertEquals("DSA", pk.getAlgorithm());

        DSAPublicKey dpk = (DSAPublicKey)pk;
        assertEquals(2048, dpk.getParams().getP().bitLength());
    }

    @Test
    public void testECPublicKey() throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0AaX3Oicz/jIVY0nHSc97YBalA96\n"
                + "4Z5QBe4xDaKDmBHFOIHhC0SLEB005o4evz3LXR+AWUZIHqyEjLAyn/vg5A==\n"
                + "-----END PUBLIC KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();

        assertTrue(entry instanceof PEMFile.PublicKeyEntry);
        PEMFile.PublicKeyEntry pubEntry = (PEMFile.PublicKeyEntry)entry;

        PublicKey pk = pubEntry.getPublicKey();
        assertEquals("EC", pk.getAlgorithm());

        ECPublicKey ecpk = (ECPublicKey)pk;
        assertNotNull(entry);
        assertEquals(256, roundBitsToByteBits(ecpk.getW().getAffineX().bitLength()));
        assertEquals(256, roundBitsToByteBits(ecpk.getW().getAffineY().bitLength()));
    }

    @Test
    public void testSOEncryptedPrivateKey() throws Exception {
        String pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI9/FSBonUacYCAggA\n"
                + "MBQGCCqGSIb3DQMHBAidGkS8wYhOpwSCBMi8JaSYOKudMNNFRpzL7QMIZgFtzDay\n"
                + "MmOroy3lW34dOa7dusqDl4d2gklKcHCpbEaTYxm5aQJ1LuiOdGtFy7HwxOvKU5xz\n"
                + "4qsJoeBIpE0eCTKjQW7/I38DzLXx2wUURqhMWOtFsWZEyR5Dqok3N9mIKKKBXAFG\n"
                + "AwNjlTRW2LyPSttiIUGN01lthjifMWoLTWB1aSGOmGeJRBdSZeqZ15xKneR4H5ja\n"
                + "yE88YcpOHCDKMIxi6ZVoKs7jDQhu8bBKqS8NsYyh1AlP9QkvWNal36jWSzhqYNzk\n"
                + "NRWUOZngfkdbMALVfRtbrC215jHGWVwosPIIs8rkoarRv8s6QWS1Rg3YfQ3qgcRf\n"
                + "s7hkDFKJf3TUXr+askfamV5hc300ZG64+ldX1YxWXY8Vd/wIvHAc/YE/lTyCgYrY\n"
                + "19Am6MNBfp8/kXvzKj+PizB8oNDO4S8sSShEEzOQ5a/+MTC6bqB0DLWYGUqRbjLc\n"
                + "PyYTC2C4i9Agx/GeGVE3c1UdtXiwwnt2XUn7Y1YGqABk0xGIY4J1NFTbSOxKl9hO\n"
                + "arwopAFrZU5nsjjFzv1DJvhfQWnYX18kPSKNHDlia019M118qZ8ERwD9tH8ix9Fa\n"
                + "R2tQdxn1aRGmvXSw+zFkbWD8aWs9n/B+QN1yllJqVoWypOld1yj+fVYYnYOtV1gK\n"
                + "eiygrtrh3JJCvLbEQl4nOgJM3PlEtfBHSaunehIXQMD1z/NDUqgBYjuDPyqRxJeH\n"
                + "Va5k72Nds5PeySKJJnICB3nZKjqgfLhNUrXa1SAQ4vqr0Ik/Lu9P7T+B1XiYwuUT\n"
                + "a20+bxi/x89ZZqwp3jnDuHup7XcO1MtqsoOKP/JgkjVMesb8Q1W8i2dXzg+l4gkk\n"
                + "l1ipreEGtT1YfFTq0DFelz6CjZFLDlGGeGWob94sW94DWTW0nsLPhQWEnwW1CcyJ\n"
                + "oJbJdDEgdiIbRJoABDkTuVXLwTlgzHSHh6zeJvNvcojI7UI3nWYCVYvD3kwghXiP\n"
                + "67sKGL3ug7PFDqLia46AudGY7CFh4+wpxyH+fidLC3FMdkDBA6xR6mGgEjRLXR9M\n"
                + "TnJ/eSYP7eqYZeKn9EarcI7v1zM2IG0/PDQCetiI0ABiHpdKyRQuuiEavp3xC5Vi\n"
                + "h7UmJNYt8Zsz3rwqAQ4FR2+Su5R34OOdRmxTaYLe96PXTpLcLef5TkYixSY7Tzgd\n"
                + "PMyRxRPrywklUEFe4KK/KOcdolxybfsIsxQnupLAMEsO7/Cs7mouNHISK51haDRc\n"
                + "vNbKQ5E4xOq1U4ThW5dHR29cGZillfmMzj05ZQh3ZX2TQJP45ahFET3v9kInWCwQ\n"
                + "8atqclVPOSnASsJZ0PxjYgKZuY8QWYM6zpfWyWnfu/CHhWbRS/qX8T1ow2SMyPBL\n"
                + "CQbZ+MhcdP0IrjoXhDFQsns16i/BPK5TTVqtEC2ywDf5P4/BOEZkySG9YNOd6THp\n"
                + "VA/dVPafzmLy3ltqH+jG8ZH2+RtWx7kwBjiDWs5cF33BFrPS7AZlzMzZoCHLXD/r\n"
                + "T/SmisybUKHMqri0x0RHeIByW0hogSByWiyIn8POabDzJV6Df9nQPziDGcSsvWfG\n"
                + "7q+hizh6+nnXOY+GZx3ptwg9mA9R4QyCiFNQradOaXSPxyEL2IC77/srFfVEIaU4\n"
                + "SRo=\n"
                + "-----END ENCRYPTED PRIVATE KEY-----"
                ;

        PEMFile pf = new PEMFile(new StringReader(pem));
        pf.setPasswordProvider(new MyPasswordProvider(new String[] { "secret", "changeit" }));

        PEMFile.Entry entry = pf.getNext();

        assertNotNull(entry);
        assertEquals(PEMFile.PrivateKeyEntry.class, entry.getClass());
        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertTrue(pk instanceof RSAPrivateKey);

        RSAPrivateKey rpk = (RSAPrivateKey)pk;

        assertEquals(2048, rpk.getModulus().bitLength());
    }

    @Test
    public void testECParameters() throws Exception {
        String pem = "-----BEGIN EC PARAMETERS-----\n"
                + "BggqhkjOPQMBBw==\n"
                + "-----END EC PARAMETERS-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size());

        PEMFile.Entry entry = entries.iterator().next();
        assertNotNull(entry);
        assertEquals(ECParametersEntry.class, entry.getClass());
    }

    @Test
    public void testECPrivateKey() throws Exception {
        String pem = "-----BEGIN EC PARAMETERS-----\n"
                + "BggqhkjOPQMBBw==\n"
                + "-----END EC PARAMETERS-----\n"
                + "-----BEGIN EC PRIVATE KEY-----\n"
                + "MHcCAQEEIBhRNFrJomNhtXs3KucIyqOzyf/1L+s2UaIVp4Y1H5JPoAoGCCqGSM49\n"
                + "AwEHoUQDQgAE0AaX3Oicz/jIVY0nHSc97YBalA964Z5QBe4xDaKDmBHFOIHhC0SL\n"
                + "EB005o4evz3LXR+AWUZIHqyEjLAyn/vg5A==\n"
                + "-----END EC PRIVATE KEY-----\n"
                ;

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(2, entries.size()); // EC Params + EC Private Key

        Iterator<PEMFile.Entry> i = entries.iterator();
        PEMFile.Entry entry = i.next();

        assertNotNull(entry);
        assertEquals(ECParametersEntry.class, entry.getClass());
        assertEquals(NamedCurve.forName("secp256r1"),
                    ((PEMFile.ECParametersEntry)entry).getECParameterSpec().getCurve());

        entry = i.next();

        assertNotNull(entry);
        assertTrue(entry instanceof PEMFile.PrivateKeyEntry);

        PEMFile.PrivateKeyEntry pke = (PEMFile.PrivateKeyEntry)entry;

        PrivateKey pk = pke.getPrivateKey();
        assertNotNull(pk);
        assertTrue(pk instanceof ECPrivateKey);
        ECPrivateKey ecpk = (ECPrivateKey)pk;

        assertEquals(256, roundBitsToByteBits(ecpk.getS().bitLength()));
    }

    @Test
    public void testX25519PrivateKeyParsing() throws Exception {
        double version = Double.parseDouble(System.getProperty("java.specification.version"));
        org.junit.Assume.assumeTrue("Java version does not support curve X25519; skipping test", version >= 11);

        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + "MDACAQAwBwYDK2VuBQAEIgQgd1l193kxJUCSLjsI4E06TzegaqK52JiVLBmuh7rdzFE=\n"
                + "-----END PRIVATE KEY-----\n"
                + "";

        Collection<PEMFile.Entry> entries = PEMFile.decode(pem);

        assertNotNull(entries);
        assertEquals(1, entries.size()); // EC Params + EC Private Key

        Iterator<PEMFile.Entry> i = entries.iterator();
        PEMFile.Entry entry = i.next();

        assertNotNull(entry);
        assertTrue(entry instanceof PEMFile.PrivateKeyEntry);
        assertEquals("XDH", ((PEMFile.PrivateKeyEntry)entry).getPrivateKey().getAlgorithm());
    }

    static class MyPasswordProvider
    implements PasswordProvider
    {
        private Iterator<String> passwords;

        public MyPasswordProvider(String[] passwordsToTry) {
            this(java.util.Arrays.asList(passwordsToTry));
        }

        public MyPasswordProvider(Collection<String> passwordsToTry) {
            passwords = passwordsToTry.iterator();
        }

        public String getPassword() {
            if(passwords.hasNext()) {
                return passwords.next();
            } else {
                return null;
            }
        }
    }
}
