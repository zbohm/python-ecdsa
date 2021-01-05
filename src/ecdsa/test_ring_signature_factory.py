try:
    import unittest2 as unittest
except ImportError:
    import unittest

import hashlib
from unittest.mock import patch

from .curves import SECP256k1, UnknownCurveError
from .ecdsa import Private_key, Public_key
from .ellipticcurve import Point
from .ring_signature_factory import (
    RingSignature,
    RingSignatureFactory,
    get_ring_signature_factory,
)
from .hash_oid import UnknownHashFuncError


secrets = (
    0xD74FE970A2B11E61BBEDDB8655454E62E69D50DE1AA69E5A77000B2944E367CD,
    0x9850FC71D8B29F4BE96903F70C8CD45CA7B1586FF1C372C237CC1B08249B78E6,
    0x29BABBA80690C3455BE9EF23791217B96783F33BC09AA2E062FF3580D7444173,
    0x7CEE71EF0C1E1AADA383E4133421031FA271F7881CEFA25A50269EC25C03C0A5,
    0xFD5815AFCD391A84D313B19DB286282781FA6391D6DD844C670825C4735BA02A,
    0x6C309FA3C2B53D178149C8B1330E26FA2A4B402827827BA658C2FB80AF4A1263,
    0xDBDFBF192685F5CD56BF41AEAFE9F2DB8F8BADA04466C73625862B19D431F08A,
    0xDB3D502331FB614A6103FBBCCC1538D5D16E4822C98D37D6611BCCA30652015F,
    0xE75D2149FECAE22B7ABAEFCB53F14CC28A3E95576B815FAEAB7195055AA2FF2B,
    0xAD4D109E2BA5EBAEC70E71B489FDC36AAC7DFBC995D311DD8EFEB93081861E41,
)
fixed_randrange = (
    0x5E45D0BA9D28E488AB2E780D0FAFBA05DDBF9056DDCC895626E2DF72134BD35F,
    0x0052D98BA7B0D046A85535C9D5AB8BCE9D652D4DD30F4A478FBA061989E04CBC,
    0x2E9130E41C8ED6105604837B089D0A4EAA2B81079EAAE2149F2EA79C2C6C16FE,
    0x81007758710D501BCF4CB2238B9FEBEAA2D1C91271419EDDB11C5938C3C7D6E8,
    0xD37B21D395ED7563111890F2C984272BDE69F12D867AB8B604AEEF029770512D,
    0x587CBBBA7D92F857AC4B5456ED35AE7E0C7CC0768F69FA01011652709AAF42D7,
    0xD8FDBEC61E3B3DD5DE0BCE0129FE514A7E13AEF8BB79A66A429B25FFC1A725C9,
    0xE7C78B020A7C5BED0F3A2397714D8EE6E87D8D4D65407841229BBE819186C0DF,
    0x80E7C3865EFE9F6CBE78DD46E23E574F4FCBF7B72E2CFCC820F27EF763C4B7A2,
    0xDA31C1CFAF44CEA455EB32FBF7F4A8C9B0B1B152FB94F087571C602F93FF8DA6,
    0x4BC265E11E0520597707E649795FAEBA3306A9F302CD84203A89CF72482AC084,
    0xB73AA0008621716F70360D2884C919CA2C12662CE8422D650DFFA0627A9A1F48,
    0x46A5A26EA838C72B144538046441EDED804B92101822D4AA66BCDF017B0F9DE1,
    0x86D1FB1B29287BE2EC33294B95673E496D99B92D7BFC69E1E4541D8CCFF9C75C,
    0x2F253D527C55B21296F4D0BF8E1AD919A188A48E86307053890C61AA40D2995C,
    0x622C637CAA5D547E2D7EBC626CE588ED383AA242B255E295D74F257EC9B52324,
    0x69F54F5ABF400C80285B35B5021ED8E41D2972A9EFC6930CD3B3196EC4109498,
    0xE1297DD9A6E87E46553784CDF23E1F9F5BF34D219017849E49E9870820539F4A,
    0x1710911DA40BE3BF831960ED2C3C8885BD5A1DC4D8404D745529A6ECAEA77E05,
    0xB36FAF519FFBBCB57BD35B554F5DD7AA2373726CCB8360FD9ADA1BBE25059DC9,
)

signature_c = (
    0x7CAF9849B6DCE78EA4C78A2C7CE8C64A8F62A92991D9E46B774F83C2F125EBD2
)
signature_s = [
    0x80E7C3865EFE9F6CBE78DD46E23E574F4FCBF7B72E2CFCC820F27EF763C4B7A2,
    0xDA31C1CFAF44CEA455EB32FBF7F4A8C9B0B1B152FB94F087571C602F93FF8DA6,
    0xD40DEAC948975F9C69C1DF2BFF67C44342A37C3264BCBFD5CCFE4D8998B15CC3,
    0x0052D98BA7B0D046A85535C9D5AB8BCE9D652D4DD30F4A478FBA061989E04CBC,
    0x2E9130E41C8ED6105604837B089D0A4EAA2B81079EAAE2149F2EA79C2C6C16FE,
    0x81007758710D501BCF4CB2238B9FEBEAA2D1C91271419EDDB11C5938C3C7D6E8,
    0xD37B21D395ED7563111890F2C984272BDE69F12D867AB8B604AEEF029770512D,
    0x587CBBBA7D92F857AC4B5456ED35AE7E0C7CC0768F69FA01011652709AAF42D7,
    0xD8FDBEC61E3B3DD5DE0BCE0129FE514A7E13AEF8BB79A66A429B25FFC1A725C9,
    0xE7C78B020A7C5BED0F3A2397714D8EE6E87D8D4D65407841229BBE819186C0DF,
]
key_image = (
    0xD20F899F3CA64FA7AD81D0621B6387D9F6DC97836FF2B54368E2507B096BCF01,
    0x6BE92D623EBCFC51B0BF1A626C7EC660106360518B34BAF49E2B38F13EE6E139,
)

message = b"Life, the Universe and Everything."


def build_keys(g, number_participants):
    private_keys, public_keys = [], []
    for i in range(number_participants):
        secret = secrets[i]
        pubkey = Public_key(g, g * secret)
        privkey = Private_key(pubkey, secret)
        public_keys.append(pubkey)
        private_keys.append(privkey)
    return private_keys, public_keys


class TestRingSignatureFactory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private_keys, public_keys = build_keys(SECP256k1.generator, 1)
        cls.pub_points = [pubkey.point for pubkey in public_keys]
        cls.private_keys, cls.public_keys = build_keys(SECP256k1.generator, 10)

    def test_hash_data(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        private_image = Point(
            SECP256k1.curve,
            0x65C68423CF08DE90A35243F2355DC6E2F5CFE18E01B754AA83C55B8DD3ACC0D,
            0x2A5D56427281C4FDE01DB96453F44276B82949B204B4016895618AB61345EEAC,
        )
        gsi_yici = Point(
            SECP256k1.curve,
            0xF10D992CEDD6087491FC2E39EDA83D5ED12C85B72285F81EB972E8EC7468A2F5,
            0x3E9D2B1F52D916B33AB65B679054FE2BACA1CED2BF9ECD563B445E0707908332,
        )
        hsi_yci = Point(
            SECP256k1.curve,
            0xF54AC0F78F8F52B14A71E691B7576FDED2A811AA4444BC11EB2C6DF3AC4DB462,
            0x72DC10578DE8AB021E403DA43E3428CBEF778EBC1E5CD5DE9233BEF627DC3497,
        )
        value = factory.hash_data(
            self.pub_points, private_image, message, gsi_yici, hsi_yci
        )
        self.assertEqual(
            value,
            0x45E236341267C16D360B6706A1D642912152CF01A52ED7D5F719CF34A07056BF,
        )

    def test_data_to_point(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        point = factory.data_to_point(self.pub_points, message)
        self.assertEqual(
            (point.x(), point.y()),
            (
                0xE525D043906146049BC72F4EA65988DF555BC6AB936939E9A0BFF08426E221AB,
                0x483F5760CEAF4D71258D10703D75D276D3DA8AEC7E2000C6D71E7D1FECF77448,
            ),
        )

    def assertOnlySignHeader(self, signature):
        self.assertEqual(signature.curve_oid, (1, 3, 132, 0, 10))
        self.assertEqual(signature.signature_length, 64)
        self.assertEqual(signature.hash_oid, (2, 16, 840, 1, 101, 3, 4, 2, 8))

    def assertSignature(self, signature):
        self.assertOnlySignHeader(signature)
        self.assertEqual(signature.checksum, signature_c)
        self.assertEqual(signature.signatures, signature_s)
        self.assertEqual(signature.key_image, key_image)

    def assertSignature2(self, signature):
        self.assertOnlySignHeader(signature)
        self.assertEqual(
            signature.checksum,
            0x1DCDD791136E7C212BC9CCA323FFF0A2B849F7D5019E9D6C30046FB503200918,
        )
        self.assertEqual(
            signature.signatures,
            [
                0x1710911DA40BE3BF831960ED2C3C8885BD5A1DC4D8404D745529A6ECAEA77E05,
                0xB36FAF519FFBBCB57BD35B554F5DD7AA2373726CCB8360FD9ADA1BBE25059DC9,
                0x0310E817B6E4602704C944BF58E3BDCCC831CF8239ABE80ECB2B14976204F0D4,
                0xB73AA0008621716F70360D2884C919CA2C12662CE8422D650DFFA0627A9A1F48,
                0x46A5A26EA838C72B144538046441EDED804B92101822D4AA66BCDF017B0F9DE1,
                0x86D1FB1B29287BE2EC33294B95673E496D99B92D7BFC69E1E4541D8CCFF9C75C,
                0x2F253D527C55B21296F4D0BF8E1AD919A188A48E86307053890C61AA40D2995C,
                0x622C637CAA5D547E2D7EBC626CE588ED383AA242B255E295D74F257EC9B52324,
                0x69F54F5ABF400C80285B35B5021ED8E41D2972A9EFC6930CD3B3196EC4109498,
                0xE1297DD9A6E87E46553784CDF23E1F9F5BF34D219017849E49E9870820539F4A,
            ],
        )
        self.assertEqual(
            signature.key_image,
            (
                0xD20F899F3CA64FA7AD81D0621B6387D9F6DC97836FF2B54368E2507B096BCF01,
                0x6BE92D623EBCFC51B0BF1A626C7EC660106360518B34BAF49E2B38F13EE6E139,
            ),
        )

    def test_sign(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange:
            signature = factory.sign(
                message, self.private_keys[2], self.public_keys, 2
            )
        self.assertEqual(mock_randrange.call_count, 10)
        self.assertSignature(signature)

    def test_verify(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        self.assertTrue(factory.verify(message, signature, self.public_keys))

    def test_verify_other_message(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        self.assertFalse(
            factory.verify(message + b"!", signature, self.public_keys)
        )

    def test_sign_and_verify(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange:
            signature = factory.sign(
                message, self.private_keys[2], self.public_keys, 2
            )
        self.assertEqual(mock_randrange.call_count, 10)
        self.assertSignature(signature)
        factory2 = get_ring_signature_factory(signature)
        self.assertTrue(factory2.verify(message, signature, self.public_keys))

    def test_get_ring_signature_factory(self):
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        factory = get_ring_signature_factory(signature)
        self.assertEqual(factory.curve.name, "SECP256k1")
        self.assertEqual(factory.hash_fnc, hashlib.sha3_256)

    def test_unknown_curve_oid(self):
        signature = RingSignature(
            (424242, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        with self.assertRaisesRegex(
            UnknownCurveError, "I don't know about the curve with oid"
        ):
            get_ring_signature_factory(signature)

    def test_unknown_hash_function(self):
        hash_func = lambda n: n
        with self.assertRaises(UnknownHashFuncError):
            RingSignatureFactory(SECP256k1, hash_func)

    def test_verify_different_public_key_order(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        public_keys = self.public_keys.copy()
        public_keys[0], public_keys[1] = public_keys[1], public_keys[0]
        self.assertFalse(factory.verify(message, signature, public_keys))

    def test_verify_less_public_keys(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        self.assertFalse(
            factory.verify(message, signature, self.public_keys[:9])
        )

    def test_verify_more_public_keys(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )
        self.assertFalse(
            factory.verify(
                message,
                signature,
                tuple(self.public_keys) + (self.public_keys[3],),
            )
        )

    def test_different_key_image(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        kim = (
            0x58DE57C639045EE67A54C9632485A2CCB0365983EAD9BF9629F66724BB9F3620,
            0xF5508FFF79E2101992D31C0023549CEFA7CDF918C6E658B71E43D2093DF24CA3,
        )
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            kim,
        )
        self.assertFalse(factory.verify(message, signature, self.public_keys))

    def test_invalid_key_image(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        kim = (key_image[0] + 1, key_image[1])
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            kim,
        )
        self.assertFalse(factory.verify(message, signature, self.public_keys))

    def test_invalid_value_c(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            42,
            signature_s,
            key_image,
        )
        self.assertFalse(factory.verify(message, signature, self.public_keys))

    def test_invalid_value_s(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        sigs = signature_s.copy()
        sigs[0] += 1
        signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            sigs,
            key_image,
        )
        self.assertFalse(factory.verify(message, signature, self.public_keys))

    def test_sign_with_other_private_key(self):
        other_secret = (
            0x504B214BEC0CFCAECE565E7BA76D4A9C469F3F411CC069B7F6FA75845F672E7D
        )
        other_pubkey = Public_key(
            SECP256k1.generator, SECP256k1.generator * other_secret
        )
        other_privkey = Private_key(other_pubkey, other_secret)
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange:
            signature = factory.sign(
                message, other_privkey, self.public_keys, 2
            )
        self.assertEqual(mock_randrange.call_count, 10)
        self.assertOnlySignHeader(signature)
        factory2 = get_ring_signature_factory(signature)
        self.assertFalse(factory2.verify(message, signature, self.public_keys))

    def test_key_image_equals(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange:
            signature1 = factory.sign(
                message, self.private_keys[2], self.public_keys, 2
            )
            signature2 = factory.sign(
                message, self.private_keys[2], self.public_keys, 2
            )
        self.assertEqual(mock_randrange.call_count, 20)
        self.assertSignature(signature1)
        self.assertOnlySignHeader(signature2)
        self.assertSignature2(signature2)
        self.assertEqual(signature1.key_image, signature2.key_image)

    def test_key_image_equals_for_pubkeys_different_order(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange1:
            signature1 = factory.sign(
                message, self.private_keys[2], self.public_keys, 2
            )
            signature2 = factory.sign(
                message,
                self.private_keys[2],
                self.public_keys[1:] + self.public_keys[:1],
                2,
            )
        self.assertEqual(mock_randrange1.call_count, 20)
        self.assertSignature(signature1)
        self.assertOnlySignHeader(signature2)
        self.assertEqual(signature1.key_image, signature2.key_image)

    def test_key_image_not_equals_for_other_message(self):
        factory = RingSignatureFactory(SECP256k1, hashlib.sha3_256)
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange1:
            signature1 = factory.sign(
                message, self.private_keys[2], self.public_keys, 2
            )
        with patch(
            "ecdsa.ring_signature_factory.randrange",
            side_effect=fixed_randrange,
        ) as mock_randrange2:
            signature2 = factory.sign(
                message + b"!", self.private_keys[2], self.public_keys, 2
            )
        self.assertEqual(mock_randrange1.call_count, 10)
        self.assertEqual(mock_randrange2.call_count, 10)
        self.assertSignature(signature1)
        self.assertOnlySignHeader(signature2)
        self.assertNotEqual(signature1.key_image, signature2.key_image)
