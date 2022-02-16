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
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * An elliptic curve with (gasp!) a discoverable name and aliases.
 *
 * Also includes a standard curves database.
 *
 * Special thanks to the following information sources which allowed me to
 * assemble this information:
 *
 *  https://neuromancer.sk/std/
 *  Oracle and/or others, Java Development Kit(s) {@link Utils#generateEllipticCurveSamples}
 *
 * @author Christopher Schultz
 */
public class NamedCurve
    extends EllipticCurve
{
    /**
     * An Elliptic Curve database.
     *
     * Note that many curves are missing.
     */
    private static final Collection<NamedCurve> CURVES = Arrays.asList(
            new NamedCurve[] {
                    // https://neuromancer.sk/std/secg/secp256r1 / prime256v1 / NIST P-256
                    new NamedCurve("1.2.840.10045.3.1.7",
                            Arrays.asList("secp256r1", "prime256v1", "NIST P-256", "P-256", "X9.62 prime256v1"),
                            new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
                            new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
                            new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
                            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
                            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
                            new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
                            0x1,
                            ASN1Stream.fromHexString("C49D360886E704936A6678E1139D26B7819F7E90")
                            ),

                    // https://neuromancer.sk/std/secg/secp384r1
                    new NamedCurve("1.3.132.0.34",
                            Arrays.asList("secp384r1", "prime384v1", "NIST P-384", "P-384", "ansip384r1"),
                            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16),
                            new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
                            new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
                            new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
                            new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
                            0x1,
                            ASN1Stream.fromHexString("A335926AA319A27A1D00896A6773A4827ACDAC73")),

                    // https://neuromancer.sk/std/secg/secp521r1
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

                    new NamedCurve("1.2.840.10045.3.1.2",
                            Arrays.asList("X9.62 prime192v2", "prime192v2"),
                            new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                            new BigInteger("cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953", 16),
                            new BigInteger("eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a", 16),
                            new BigInteger("6574d11d69b6ec7a672bb82a083df2f2b0847de970b2de15", 16),
                            new BigInteger("fffffffffffffffffffffffe5fb1a724dc80418648d8dd31", 16),
                            0x1,
                            ASN1Stream.fromHexString("31A92EE2029FD10D901B113E990710F0D21AC6B6")
                            ),

                    new NamedCurve("1.2.840.10045.3.1.3",
                            Arrays.asList("X9.62 prime192v3", "prime192v3"),
                            new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                            new BigInteger("22123dc2395a05caa7423daeccc94760a7d462256bd56916", 16),
                            new BigInteger("7d29778100c65a1da1783716588dce2b8b4aee8e228f1896", 16),
                            new BigInteger("38a90f22637337334b49dcb66a6dc8f9978aca7648a943b0", 16),
                            new BigInteger("ffffffffffffffffffffffff7a62d031c83f4294f640ec13", 16),
                            0x1,
                            ASN1Stream.fromHexString("C469684435DEB378C4B65CA9591E2A5763059A2E")
                            ),

                    new NamedCurve("1.2.840.10045.3.1.4",
                            Arrays.asList("X9.62 prime239v1", "prime239v1"),
                            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
                            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
                            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16),
                            new BigInteger("ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16),
                            new BigInteger("7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae", 16),
                            new BigInteger("7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b", 16),
                            0x1,
                            ASN1Stream.fromHexString("E43BB460F0B80CC0C0B075798E948060F8321B7D")
                            ),

                    new NamedCurve("1.2.840.10045.3.1.5",
                            Arrays.asList("X9.62 prime239v2", "prime239v2"),
                            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
                            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
                            new BigInteger("617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c", 16),
                            new BigInteger("38af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7", 16),
                            new BigInteger("5b0125e4dbea0ec7206da0fc01d9b081329fb555de6ef460237dff8be4ba", 16),
                            new BigInteger("7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063", 16),
                            0x1,
                            ASN1Stream.fromHexString("E8B4011604095303CA3B8099982BE09FCB9AE616")
                            ),

                    new NamedCurve("1.2.840.10045.3.1.6",
                            Arrays.asList("X9.62 prime239v3", "prime239v3"),
                            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
                            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
                            new BigInteger("255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e", 16),
                            new BigInteger("6768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a", 16),
                            new BigInteger("1607e6898f390c06bc1d552bad226f3b6fcfe48b6e818499af18e3ed6cf3", 16),
                            new BigInteger("7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551", 16),
                            0x1,
                            ASN1Stream.fromHexString("7D7374168FFE3471B60A857686A19475D3BFA2FF")
                            ),

                    new NamedCurve("1.3.36.3.3.2.8.1.1.7",
                            Arrays.asList("brainpoolP256r1"),
                            new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
                            new BigInteger("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9", 16),
                            new BigInteger("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6", 16),
                            new BigInteger("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262", 16),
                            new BigInteger("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997", 16),
                            new BigInteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.3.36.3.3.2.8.1.1.9",
                            Arrays.asList("brainpoolP320r1"),
                            new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", 16),
                            new BigInteger("3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4", 16),
                            new BigInteger("520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6", 16),
                            new BigInteger("43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611", 16),
                            new BigInteger("14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1", 16),
                            new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.3.36.3.3.2.8.1.1.11",
                            Arrays.asList("brainpoolP384r1"),
                            new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", 16),
                            new BigInteger("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826", 16),
                            new BigInteger("4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11", 16),
                            new BigInteger("1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e", 16),
                            new BigInteger("8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315", 16),
                            new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.3.36.3.3.2.8.1.1.13",
                            Arrays.asList("brainpoolP512r1"),
                            new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", 16),
                            new BigInteger("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca", 16),
                            new BigInteger("3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723", 16),
                            new BigInteger("81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822", 16),
                            new BigInteger("7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892", 16),
                            new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.3.132.0.6",
                            Arrays.asList("secp112r1"),
                            new BigInteger("db7c2abf62e35e668076bead208b", 16),
                            new BigInteger("db7c2abf62e35e668076bead2088", 16),
                            new BigInteger("659ef8ba043916eede8911702b22", 16),
                            new BigInteger("9487239995a5ee76b55f9c2f098", 16),
                            new BigInteger("a89ce5af8724c0a23e0e0ff77500", 16),
                            new BigInteger("db7c2abf62e35e7628dfac6561c5", 16),
                            0x1,
                            ASN1Stream.fromHexString("00F50B028E4D696E676875615175290472783FB1")
                            ),

                    new NamedCurve("1.3.132.0.7",
                            Arrays.asList("secp112r2"),
                            new BigInteger("db7c2abf62e35e668076bead208b", 16),
                            new BigInteger("6127c24c05f38a0aaaf65c0ef02c", 16),
                            new BigInteger("51def1815db5ed74fcc34c85d709", 16),
                            new BigInteger("4ba30ab5e892b4e1649dd0928643", 16),
                            new BigInteger("adcd46f5882e3747def36e956e97", 16),
                            new BigInteger("36df0aafd8b8d7597ca10520d04b", 16),
                            0x4,
                            ASN1Stream.fromHexString("002757A1114D696E6768756151755316C05E0BD4")
                            ),

                    new NamedCurve("1.3.132.0.28",
                            Arrays.asList("secp128r1"),
                            new BigInteger("fffffffdffffffffffffffffffffffff", 16),
                            new BigInteger("fffffffdfffffffffffffffffffffffc", 16),
                            new BigInteger("e87579c11079f43dd824993c2cee5ed3", 16),
                            new BigInteger("161ff7528b899b2d0c28607ca52c5b86", 16),
                            new BigInteger("cf5ac8395bafeb13c02da292dded7a83", 16),
                            new BigInteger("fffffffe0000000075a30d1b9038a115", 16),
                            0x1,
                            ASN1Stream.fromHexString("000E0D4D696E6768756151750CC03A4473D03679")
                            ),

                    new NamedCurve("1.3.132.0.29",
                            Arrays.asList("secp128r2"),
                            new BigInteger("fffffffdffffffffffffffffffffffff", 16),
                            new BigInteger("d6031998d1b3bbfebf59cc9bbff9aee1", 16),
                            new BigInteger("5eeefca380d02919dc2c6558bb6d8a5d", 16),
                            new BigInteger("7b6aa5d85e572983e6fb32a7cdebc140", 16),
                            new BigInteger("27b6916a894d3aee7106fe805fc34b44", 16),
                            new BigInteger("3fffffff7fffffffbe0024720613b5a3", 16),
                            0x4,
                            ASN1Stream.fromHexString("004D696E67687561517512D8F03431FCE63B88F4")
                            ),

                    new NamedCurve("1.3.132.0.9",
                            Arrays.asList("secp160k1", "ansip160k1"),
                            new BigInteger("fffffffffffffffffffffffffffffffeffffac73", 16),
                            new BigInteger("0", 16),
                            new BigInteger("7", 16),
                            new BigInteger("3b4c382ce37aa192a4019e763036f4f5dd4d7ebb", 16),
                            new BigInteger("938cf935318fdced6bc28286531733c3f03c4fee", 16),
                            new BigInteger("100000000000000000001b8fa16dfab9aca16b6b3", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.3.132.0.8",
                            Arrays.asList("secp160r1", "ansip160r1"),
                            new BigInteger("ffffffffffffffffffffffffffffffff7fffffff", 16),
                            new BigInteger("ffffffffffffffffffffffffffffffff7ffffffc", 16),
                            new BigInteger("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16),
                            new BigInteger("4a96b5688ef573284664698968c38bb913cbfc82", 16),
                            new BigInteger("23a628553168947d59dcc912042351377ac5fb32", 16),
                            new BigInteger("100000000000000000001f4c8f927aed3ca752257", 16),
                            0x1,
                            ASN1Stream.fromHexString("1053CDE42C14D696E67687561517533BF3F83345")
                            ),

                    new NamedCurve("1.3.132.0.30",
                            Arrays.asList("secp160r2", "ansip160r2"),
                            new BigInteger("fffffffffffffffffffffffffffffffeffffac73", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffeffffac70", 16),
                            new BigInteger("b4e134d3fb59eb8bab57274904664d5af50388ba", 16),
                            new BigInteger("52dcb034293a117e1f4ff11b30f7199d3144ce6d", 16),
                            new BigInteger("feaffef2e331f296e071fa0df9982cfea7d43f2e", 16),
                            new BigInteger("100000000000000000000351ee786a818f3a1a16b", 16),
                            0x1,
                            ASN1Stream.fromHexString("B99B99B099B323E02709A4D696E6768756151751")
                            ),

                    new NamedCurve("1.3.132.0.31",
                            Arrays.asList("secp192k1", "ansip192k1"),
                            new BigInteger("fffffffffffffffffffffffffffffffffffffffeffffee37", 16),
                            new BigInteger("0", 16),
                            new BigInteger("3", 16),
                            new BigInteger("db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d", 16),
                            new BigInteger("9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d", 16),
                            new BigInteger("fffffffffffffffffffffffe26f2fc170f69466a74defd8d", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.2.840.10045.3.1.1",
                            Arrays.asList("secp192r1", "P-192", "prime192v1"),
                            new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
                            new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                            new BigInteger("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16),
                            new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
                            0x1,
                            ASN1Stream.fromHexString("3045AE6FC8422F64ED579528D38120EAE12196D5")
                            ),

                    new NamedCurve("1.3.132.0.32",
                            Arrays.asList("secp224k1", "ansip224k1"),
                            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d", 16),
                            new BigInteger("0", 16),
                            new BigInteger("5", 16),
                            new BigInteger("a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c", 16),
                            new BigInteger("7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5", 16),
                            new BigInteger("10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7", 16),
                            0x1,
                            null
                            ),

                    new NamedCurve("1.3.132.0.33",
                            Arrays.asList("secp224r1", "P-224", "ansip224r1"),
                            new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", 16),
                            new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
                            new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16),
                            new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
                            new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16),
                            0x1,
                            ASN1Stream.fromHexString("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5")
                            ),

                    new NamedCurve("1.3.132.0.10",
                            Arrays.asList("secp256k1", "ansip256k1"),
                            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
                            new BigInteger("0", 16),
                            new BigInteger("7", 16),
                            new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
                            new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
                            new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
                            0x1,
                            null
                    ),

                    new NamedCurve("1.2.840.10045.3.0.5",
                            Arrays.asList("X9.62 c2tnb191v1", "c2tnb191v1"),
                            191,
                            new int[] { 9 },
                            new BigInteger("2866537b676752636a68f56554e12640276b649ef7526267", 16),
                            new BigInteger("2e45ef571f00786f67b0081b9495a3d95462f5de0aa185ec", 16),
                            new BigInteger("36b3daf8a23206f9c4f299d7b21a9c369137f2c84ae1aa0d", 16),
                            new BigInteger("765be73433b3f95e332932e70ea245ca2418ea0ef98018fb", 16),
                            new BigInteger("40000000000000000000000004a20e90c39067c893bbb9a5", 16),
                            0x2,
                            ASN1Stream.fromHexString("4E13CA542744D696E67687561517552F279A8C84")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.6",
                            Arrays.asList("X9.62 c2tnb191v2", "c2tnb191v2"),
                            191,
                            new int[] { 9 },
                            new BigInteger("401028774d7777c7b7666d1366ea432071274f89ff01e718", 16),
                            new BigInteger("620048d28bcbd03b6249c99182b7c8cd19700c362c46a01", 16),
                            new BigInteger("3809b2b7cc1b28cc5a87926aad83fd28789e81e2c9e3bf10", 16),
                            new BigInteger("17434386626d14f3dbf01760d9213a3e1cf37aec437d668a", 16),
                            new BigInteger("20000000000000000000000050508cb89f652824e06b8173", 16),
                            0x4,
                            ASN1Stream.fromHexString("0871EF2FEF24D696E6768756151758BEE0D95C15")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.7",
                            Arrays.asList("X9.62 c2tnb191v3", "c2tnb191v3"),
                            191,
                            new int[] { 9 },
                            new BigInteger("6c01074756099122221056911c77d77e77a777e7e7e77fcb", 16),
                            new BigInteger("71fe1af926cf847989efef8db459f66394d90f32ad3f15e8", 16),
                            new BigInteger("375d4ce24fde434489de8746e71786015009e66e38a926dd", 16),
                            new BigInteger("545a39176196575d985999366e6ad34ce0a77cd7127b06be", 16),
                            new BigInteger("155555555555555555555555610c0b196812bfb6288a3ea3", 16),
                            0x6,
                            ASN1Stream.fromHexString("E053512DC684D696E676875615175067AE786D1F")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.11",
                            Arrays.asList("X9.62 c2tnb239v1", "c2tnb239v1"),
                            239,
                            new int[] { 36 },
                            new BigInteger("32010857077c5431123a46b808906756f543423e8d27877578125778ac76", 16),
                            new BigInteger("790408f2eedaf392b012edefb3392f30f4327c0ca3f31fc383c422aa8c16", 16),
                            new BigInteger("57927098fa932e7c0a96d3fd5b706ef7e5f5c156e16b7e7c86038552e91d", 16),
                            new BigInteger("61d8ee5077c33fecf6f1a16b268de469c3c7744ea9a971649fc7a9616305", 16),
                            new BigInteger("2000000000000000000000000000000f4d42ffe1492a4993f1cad666e447", 16),
                            0x4,
                            ASN1Stream.fromHexString("D34B9A4D696E676875615175CA71B920BFEFB05D")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.12",
                            Arrays.asList("X9.62 c2tnb239v2", "c2tnb239v2"),
                            239,
                            new int[] { 36 },
                            new BigInteger("4230017757a767fae42398569b746325d45313af0766266479b75654e65f", 16),
                            new BigInteger("5037ea654196cff0cd82b2c14a2fcf2e3ff8775285b545722f03eacdb74b", 16),
                            new BigInteger("28f9d04e900069c8dc47a08534fe76d2b900b7d7ef31f5709f200c4ca205", 16),
                            new BigInteger("5667334c45aff3b5a03bad9dd75e2c71a99362567d5453f7fa6e227ec833", 16),
                            new BigInteger("1555555555555555555555555555553c6f2885259c31e3fcdf154624522d", 16),
                            0x6,
                            ASN1Stream.fromHexString("2AA6982FDFA4D696E676875615175D266727277D")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.13",
                            Arrays.asList("X9.62 c2tnb239v3", "c2tnb239v3"),
                            239,
                            new int[] { 36 },
                            new BigInteger("1238774666a67766d6676f778e676b66999176666e687666d8766c66a9f", 16),
                            new BigInteger("6a941977ba9f6a435199acfc51067ed587f519c5ecb541b8e44111de1d40", 16),
                            new BigInteger("70f6e9d04d289c4e89913ce3530bfde903977d42b146d539bf1bde4e9c92", 16),
                            new BigInteger("2e5a0eaf6e5e1305b9004dce5c0ed7fe59a35608f33837c816d80b79f461", 16),
                            new BigInteger("cccccccccccccccccccccccccccccac4912d2d9df903ef9888b8a0e4cff", 16),
                            0xa,
                            ASN1Stream.fromHexString("9E076F4D696E676875615175E11E9FDD")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.18",
                            Arrays.asList("X9.62 c2tnb359v1", "c2tnb359v1"),
                            359,
                            new int[] { 68 },
                            new BigInteger("5667676a654b20754f356ea92017d946567c46675556f19556a04616b567d223a5e05656fb549016a96656a557", 16),
                            new BigInteger("2472e2d0197c49363f1fe7f5b6db075d52b6947d135d8ca445805d39bc345626089687742b6329e70680231988", 16),
                            new BigInteger("3c258ef3047767e7ede0f1fdaa79daee3841366a132e163aced4ed2401df9c6bdcde98e8e707c07a2239b1b097", 16),
                            new BigInteger("53d7e08529547048121e9c95f3791dd804963948f34fae7bf44ea82365dc7868fe57e4ae2de211305a407104bd", 16),
                            new BigInteger("1af286bca1af286bca1af286bca1af286bca1af286bc9fb8f6b85c556892c20a7eb964fe7719e74f490758d3b", 16),
                            0x4c,
                            ASN1Stream.fromHexString("2B354920B724D696E67687561517585BA1332DC6")
                            ),

                    new NamedCurve("1.2.840.10045.3.0.20",
                            Arrays.asList("X9.62 c2tnb431r1", "c2tnb431r1"),
                            431,
                            new int[] { 120 },
                            new BigInteger("1a827ef00dd6fc0e234caf046c6a5d8a85395b236cc4ad2cf32a0cadbdc9ddf620b0eb9906d0957f6c6feacd615468df104de296cd8f", 16),
                            new BigInteger("10d9b4a3d9047d8b154359abfb1b7f5485b04ceb868237ddc9deda982a679a5a919b626d4e50a8dd731b107a9962381fb5d807bf2618", 16),
                            new BigInteger("120fc05d3c67a99de161d2f4092622feca701be4f50f4758714e8a87bbf2a658ef8c21e7c5efe965361f6c2999c0c247b0dbd70ce6b7", 16),
                            new BigInteger("20d0af8903a96f8d5fa2c255745d3c451b302c9346d9b7e485e7bce41f6b591f3e8f6addcbb0bc4c2f947a7de1a89b625d6a598b3760", 16),
                            new BigInteger("340340340340340340340340340340340340340340340340340340323c313fab50589703b5ec68d3587fec60d161cc149c1ad4a91", 16),
                            0x2760,
                            null
                            ),


                    new NamedCurve("1.3.132.0.4",
                            Arrays.asList("sect113r1"),
                            113,
                            new int[] { 9 },
                            new BigInteger("3088250ca6e7c7fe649ce85820f7", 16),
                            new BigInteger("e8bee4d3e2260744188be0e9c723", 16),
                            new BigInteger("9d73616f35f4ab1407d73562c10f", 16),
                            new BigInteger("a52830277958ee84d1315ed31886", 16),
                            new BigInteger("100000000000000d9ccec8a39e56f", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.5",
                            Arrays.asList("sect113r2"),
                            113,
                            new int[] { 9 },
                            new BigInteger("689918dbec7e5a0dd6dfc0aa55c7", 16),
                            new BigInteger("95e9a9ec9b297bd4bf36e059184f", 16),
                            new BigInteger("1a57a6a7b26ca5ef52fcdb8164797", 16),
                            new BigInteger("b3adc94ed1fe674c06e695baba1d", 16),
                            new BigInteger("10000000000000108789b2496af93", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.22",
                            Arrays.asList("sect131r1"),
                            131,
                            new int[] { 8,3,2 },
                            new BigInteger("7a11b09a76b562144418ff3ff8c2570b8", 16),
                            new BigInteger("217c05610884b63b9c6c7291678f9d341", 16),
                            new BigInteger("81baf91fdf9833c40f9c181343638399", 16),
                            new BigInteger("78c6e7ea38c001f73c8134b1b4ef9e150", 16),
                            new BigInteger("400000000000000023123953a9464b54d", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.23",
                            Arrays.asList("sect131r2"),
                            131,
                            new int[] { 8,3,2 },
                            new BigInteger("3e5a88919d7cafcbf415f07c2176573b2", 16),
                            new BigInteger("4b8266a46c55657ac734ce38f018f2192", 16),
                            new BigInteger("356dcd8f2f95031ad652d23951bb366a8", 16),
                            new BigInteger("648f06d867940a5366d9e265de9eb240f", 16),
                            new BigInteger("400000000000000016954a233049ba98f", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.1",
                            Arrays.asList("sect163k1", "K-163", "ansit163k1"),
                            163,
                            new int[] { 7,6,3 },
                            new BigInteger("1", 16),
                            new BigInteger("1", 16),
                            new BigInteger("2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8", 16),
                            new BigInteger("289070fb05d38ff58321f2e800536d538ccdaa3d9", 16),
                            new BigInteger("4000000000000000000020108a2e0cc0d99f8a5ef", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.2",
                            Arrays.asList("sect163r1", "ansit163r1"),
                            163,
                            new int[] { 7,6,3 },
                            new BigInteger("7b6882caaefa84f9554ff8428bd88e246d2782ae2", 16),
                            new BigInteger("713612dcddcb40aab946bda29ca91f73af958afd9", 16),
                            new BigInteger("369979697ab43897789566789567f787a7876a654", 16),
                            new BigInteger("435edb42efafb2989d51fefce3c80988f41ff883", 16),
                            new BigInteger("3ffffffffffffffffffff48aab689c29ca710279b", 16),
                            0x2,
                            ASN1Stream.fromHexString("24B7B137C8A14D696E6768756151756FD0DA2E5C")
                            ),

                    new NamedCurve("1.3.132.0.15",
                            Arrays.asList("sect163r2", "B-163", "ansit163r2"),
                            163,
                            new int[] { 7,6,3 },
                            new BigInteger("1", 16),
                            new BigInteger("20a601907b8c953ca1481eb10512f78744a3205fd", 16),
                            new BigInteger("3f0eba16286a2d57ea0991168d4994637e8343e36", 16),
                            new BigInteger("d51fbc6c71a0094fa2cdd545b11c5c0c797324f1", 16),
                            new BigInteger("40000000000000000000292fe77e70c12a4234c33", 16),
                            0x2,
                            ASN1Stream.fromHexString("85E25BFE5C86226CDB12016F7553F9D0E693A268")
                            ),

                    new NamedCurve("1.3.132.0.24",
                            Arrays.asList("sect193r1", "ansit193r1"),
                            193,
                            new int[] { 15 },
                            new BigInteger("17858feb7a98975169e171f77b4087de098ac8a911df7b01", 16),
                            new BigInteger("fdfb49bfe6c3a89facadaa7a1e5bbc7cc1c2e5d831478814", 16),
                            new BigInteger("1f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1", 16),
                            new BigInteger("25e399f2903712ccf3ea9e3a1ad17fb0b3201b6af7ce1b05", 16),
                            new BigInteger("1000000000000000000000000c7f34a778f443acc920eba49", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.25",
                            Arrays.asList("sect193r2", "ansit193r2"),
                            193,
                            new int[] { 15 },
                            new BigInteger("163f35a5137c2ce3ea6ed8667190b0bc43ecd69977702709b", 16),
                            new BigInteger("c9bb9e8927d4d64c377e2ab2856a5b16e3efb7f61d4316ae", 16),
                            new BigInteger("d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f", 16),
                            new BigInteger("1ce94335607c304ac29e7defbd9ca01f596f927224cdecf6c", 16),
                            new BigInteger("10000000000000000000000015aab561b005413ccd4ee99d5", 16),
                            0x2,
                            null
                            ),

                    new NamedCurve("1.3.132.0.26",
                            Arrays.asList("sect233k1", "K-233", "ansit233k1"),
                            233,
                            new int[] { 74 },
                            new BigInteger("0", 16),
                            new BigInteger("1", 16),
                            new BigInteger("17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126", 16),
                            new BigInteger("1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3", 16),
                            new BigInteger("8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf", 16),
                            0x4,
                            null
                            ),

                    new NamedCurve("1.3.132.0.27",
                            Arrays.asList("sect233r1", "B-233", "ansit233r1"),
                            233,
                            new int[] { 74 },
                            new BigInteger("1", 16),
                            new BigInteger("66647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad", 16),
                            new BigInteger("fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b", 16),
                            new BigInteger("1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052", 16),
                            new BigInteger("1000000000000000000000000000013e974e72f8a6922031d2603cfe0d7", 16),
                            0x2,
                            ASN1Stream.fromHexString("74D59FF07F6B413D0EA14B344B20A2DB049B50C3")
                            ),

                    new NamedCurve("1.3.132.0.3",
                            Arrays.asList("sect239k1", "ansit239k1"),
                            239,
                            new int[] { 158 },
                            new BigInteger("0", 16),
                            new BigInteger("1", 16),
                            new BigInteger("29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dc", 16),
                            new BigInteger("76310804f12e549bdb011c103089e73510acb275fc312a5dc6b76553f0ca", 16),
                            new BigInteger("2000000000000000000000000000005a79fec67cb6e91f1c1da800e478a5", 16),
                            0x4,
                            null
                            ),

                    new NamedCurve("1.3.132.0.16",
                            Arrays.asList("sect283k1", "K-283", "ansit283k1"),
                            283,
                            new int[] { 12,7,5 },
                            new BigInteger("0", 16),
                            new BigInteger("1", 16),
                            new BigInteger("503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836", 16),
                            new BigInteger("1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259", 16),
                            new BigInteger("1ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61", 16),
                            0x4,
                            null
                            ),

                    new NamedCurve("1.3.132.0.17",
                            Arrays.asList("sect283r1", "B-283", "ansit283r1"),
                            283,
                            new int[] { 12,7,5 },
                            new BigInteger("1", 16),
                            new BigInteger("27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", 16),
                            new BigInteger("5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", 16),
                            new BigInteger("3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4", 16),
                            new BigInteger("3ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307", 16),
                            0x2,
                            ASN1Stream.fromHexString("77E2B07370EB0F832A6DD5B62DFC88CD06BB84BE")
                            ),

                    new NamedCurve("1.3.132.0.36",
                            Arrays.asList("sect409k1", "K-409", "ansit409k1"),
                            409,
                            new int[] { 87 },
                            new BigInteger("0", 16),
                            new BigInteger("1", 16),
                            new BigInteger("60f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746", 16),
                            new BigInteger("1e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b", 16),
                            new BigInteger("7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf", 16),
                            0x4,
                            null
                            ),

                    new NamedCurve("1.3.132.0.37",
                            Arrays.asList("sect409r1", "B-409", "ansit409r1"),
                            409,
                            new int[] { 87 },
                            new BigInteger("1", 16),
                            new BigInteger("21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16),
                            new BigInteger("15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16),
                            new BigInteger("61b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16),
                            new BigInteger("10000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173", 16),
                            0x2,
                            ASN1Stream.fromHexString("4099B5A457F9D69F79213D094C4BCD4D4262210B")
                            ),

                    new NamedCurve("1.3.132.0.38",
                            Arrays.asList("sect571k1", "K-571", "ansit571k1"),
                            571,
                            new int[] { 10,5,2 },
                            new BigInteger("0", 16),
                            new BigInteger("1", 16),
                            new BigInteger("26eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972", 16),
                            new BigInteger("349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3", 16),
                            new BigInteger("20000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001", 16),
                            0x4,
                            null
                            ),

                    new NamedCurve("1.3.132.0.39",
                            Arrays.asList("sect571r1", "B-571", "ansit571r1"),
                            571,
                            new int[] { 10,5,2 },
                            new BigInteger("1", 16),
                            new BigInteger("2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", 16),
                            new BigInteger("303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19", 16),
                            new BigInteger("37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b", 16),
                            new BigInteger("3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47", 16),
                            0x2,
                            ASN1Stream.fromHexString("2AA058F73A0E33AB486B0F610410C53A7F132310")
                            ),

                    // TODO: How best to identify these curves?
                    new NamedCurve("1.3.101.110",
                            Arrays.asList("X25519"),
                            2, new int[] { 1 }, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, 0, null),

                    new NamedCurve("1.3.101.111",
                            Arrays.asList("X448"),
                            2, new int[] { 1 }, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, 0, null),
            }
            );
    private static final Map<String,NamedCurve> CURVES_BY_OID;
    private static final Map<String,NamedCurve> CURVES_BY_NAME;
    static {
        Map<String,NamedCurve> oidCurveMap = new HashMap<String,NamedCurve>(CURVES.size());
        Map<String,NamedCurve> nameCurveMap = new HashMap<String,NamedCurve>();
        for(NamedCurve c : CURVES) {
            if(PEMFile.X25519_OID.equals(c.getOID())) {
                try {
                    Class<?> namedParameterClass = Class.forName("java.security.spec.NamedParameterSpec");
                    Field f = namedParameterClass.getField("X25519");
                    f.get(null);
                } catch (Exception e) {
                    // System.out.println("Can't handle X25519 curve");
                }
            }
            if(oidCurveMap.containsKey(c.getOID())) {
                throw new IllegalStateException("Curve with OID " + c.getOID() + " has already been defined");
            }
            oidCurveMap.put(c.getOID(), c);
            for(String name : c.getNames()) {
                if(nameCurveMap.containsKey(name)) {
                    throw new IllegalStateException("Curve with name " + name + " has already been defined");
                }
                nameCurveMap.put(name, c);
            }
        }

        CURVES_BY_OID = Collections.unmodifiableMap(oidCurveMap);
        CURVES_BY_NAME = Collections.unmodifiableMap(nameCurveMap);
    }

    /**
     * Gets a NamedCurve by its Object Identifier (OID).
     *
     * @param oid The OID of the desired curve.
     *
     * @return The NamedCurve with the specified OID, or {@code null} if no
     *         such curve can be found in this curve database.
     */
    public static NamedCurve forOID(String oid) {
        return CURVES_BY_OID.get(oid);
    }

    /**
     * Gets a NamedCurve by its name (or alias).
     *
     * @param name The name (or alias) of the desired curve.
     *
     * @return The NamedCurve with the specified name (or alias), or
     *         {@code null} if no such curve can be found in this curve
     *         database.
     */
    public static NamedCurve forName(String name) {
        return CURVES_BY_NAME.get(name);
    }

    /**
     * Gets a NamedCurve for an EllipticCurve instance.
     *
     * @param ec The instance of an EllipticCurve of the desired curve.
     *
     * @return The NamedCurve which matches all of the parameters of the
     *         specified EllipticCurve, or {@code null} if no such curve can
     *         be found in this curve database.
     */
    public static NamedCurve forCurve(EllipticCurve ec) {
        if(ec instanceof NamedCurve) {
            return (NamedCurve)ec;
        }

        for(NamedCurve curve : CURVES) {
            if(ec.equals(curve)) {
                return curve;
            }
        }
        return null;
    }

    private final String oid;
    // Curves have either p or m+ks
    private final BigInteger p;
    private final int m;
    private final int[] ks;
    private final BigInteger x;
    private final BigInteger y;
    private final BigInteger n;
    private final int h;
    private final Collection<String> names;

    private final String string;

    /**
     * Create a new NameCurve with a an F2m field.
     *
     * @param oid The OID of the curve.
     * @param names A collection of names and aliases of the curve.
     * @param m
     * @param ks
     * @param a
     * @param b
     * @param x
     * @param y
     * @param n
     * @param h
     * @param seed
     */
    public NamedCurve(String oid,
            Collection<String> names,
            int m,
            int[] ks,
            BigInteger a, BigInteger b,
            BigInteger x, BigInteger y,
            BigInteger n, int h,
            byte[] seed)
    {
        super(new ECFieldF2m(m, ks), a, b, seed);

        if(null == names) {
            this.names = null;
        } else {
            this.names = Collections.unmodifiableCollection(new ArrayList<String>(names));
        }
        this.oid = oid;
        this.m = m;
        this.ks = ks.clone();
        this.p = null;
        this.x = x;
        this.y = y;
        this.n = n;
        this.h = h;

        string = toString(oid, names);
    }

    /**
     * Creates a new NamedCurve with an Fp field.
     * @param oid The OID of the curve.
     * @param names A collection of names and aliases of the curve.
     * @param p
     * @param a
     * @param b
     * @param x
     * @param y
     * @param n
     * @param h
     * @param seed
     */
    public NamedCurve(String oid,
                      Collection<String> names,
                      BigInteger p,
                      BigInteger a, BigInteger b,
                      BigInteger x, BigInteger y,
                      BigInteger n, int h,
                      byte[] seed)
    {
        super(new ECFieldFp(p), a, b, seed);

        if(null == names) {
            this.names = null;
        } else {
            this.names = Collections.unmodifiableCollection(new ArrayList<String>(names));
        }

        this.oid = oid;
        this.p = p;
        this.m = 0;
        this.ks = null;
        this.x = x;
        this.y = y;
        this.n = n;
        this.h = h;

        string = toString(oid, names);
    }

    private static String toString(String oid, Collection<String> names) {
        StringBuilder sb = new StringBuilder("NamedCurve { oid=").append(oid);
        if(null != names) {
            boolean first = true;
            for(String name : names) {
                if(!oid.equals(name)) {
                    if(first) {
                        first = false;
                        sb.append(", names=[");
                    } else {
                        sb.append(", ");
                    }
                    sb.append(name);
                }
            }
            if(!first) {
                sb.append(']');
            }
        }
        sb.append(" }");

        return sb.toString();
    }

    public String getOID() {
        return oid;
    }

    /**
     * Returns a collection of all curve names and aliases.
     *
     * @return All available curve names and aliases.
     */
    public Collection<String> getNames() {
        return names;
    }

    /**
     * Returns the point P for the curve. Note that some curves do not have a
     * point 'P' and these will return null. Those curves should have a
     * non-zero {@link #getM} value and non-null {@link #getKs} array.
     *
     * @return The point P for this curve, or <code>null</code> if the curve
     *         does not have a point 'P'.
     *
     * @see #getM
     * @see #getKs
     */
    public BigInteger getP() {
        return p;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public BigInteger getN() {
        return n;
    }

    public int getH() {
        return h;
    }

    /**
     * Returns the value M for the curve. Note that some curves do not have an
     * 'M' value and this will return 0 (zero). Those curves should have a
     * non-null {@link #getP} value.
     *
     * @return The value M for this curve, or <code>0</code> if the curve
     *         does not have an 'M' value.
     *
     * @see #getP
     * @see #getKs
     */
    public int getM() {
        return m;
    }

    /**
     * Returns the ks array for the curve. Note that some curves do not have an
     * array of ks and this will return null. Those curves should have a
     * non-null {@link #getP} value.
     *
     * @return The array of ks for this curve, or <code>null</code> if the curve
     *         does not have a ks array.
     *
     * @see #getP
     * @see #getM
     */
    public int[] getKs() {
        if(null == ks) {
            return null;
        } else {
            return ks.clone();
        }
    }

    @Override
    public boolean equals(Object o) {
        // Explicitly inherit the superclass behavior

        return super.equals(o);
    }

    @Override
    public int hashCode() {
        // Explicitly inherit the superclass behavior

        return super.hashCode();
    }

    @Override
    public String toString() {
        return string;
    }
}