try:
    import unittest2 as unittest
except ImportError:
    import unittest

import asn1

from .ring_signature import (RingSignature, SignatureInvalidFormat,
                             peek_sequence, read_der_int, read_der_octet,
                             read_der_oid, read_der_tag, seq_to_str,
                             signature_from_der, signature_from_pem,
                             str_to_seq)

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
singature_der = (
    b"\x04\nLiuWeiWong\x02\x01\x01\x06\x05+\x81\x04\x00\n\x06\t`\x86H"
    b"\x01e\x03\x04\x02\x080E\x02!\x00\xd2\x0f\x89\x9f<\xa6O\xa7\xad"
    b"\x81\xd0b\x1bc\x87\xd9\xf6\xdc\x97\x83o\xf2\xb5Ch\xe2P{\tk\xcf"
    b"\x01\x02 k\xe9-b>\xbc\xfcQ\xb0\xbf\x1abl~\xc6`\x10c`Q\x8b4\xba"
    b"\xf4\x9e+8\xf1>\xe6\xe19\x02 |\xaf\x98I\xb6\xdc\xe7\x8e\xa4\xc7"
    b"\x8a,|\xe8\xc6J\x8fb\xa9)\x91\xd9\xe4kwO\x83\xc2\xf1%\xeb\xd20"
    b"\x82\x01Z\x02!\x00\x80\xe7\xc3\x86^\xfe\x9fl\xbex\xddF\xe2>WOO"
    b"\xcb\xf7\xb7.,\xfc\xc8 \xf2~\xf7c\xc4\xb7\xa2\x02!\x00\xda1\xc1"
    b"\xcf\xafD\xce\xa4U\xeb2\xfb\xf7\xf4\xa8\xc9\xb0\xb1\xb1R\xfb\x94"
    b"\xf0\x87W\x1c`/\x93\xff\x8d\xa6\x02!\x00\xd4\r\xea\xc9H\x97_\x9ci"
    b"\xc1\xdf+\xffg\xc4CB\xa3|2d\xbc\xbf\xd5\xcc\xfeM\x89\x98\xb1\\\xc3"
    b"\x02\x1fR\xd9\x8b\xa7\xb0\xd0F\xa8U5\xc9\xd5\xab\x8b\xce\x9de-M\xd3"
    b"\x0fJG\x8f\xba\x06\x19\x89\xe0L\xbc\x02 .\x910\xe4\x1c\x8e\xd6"
    b"\x10V\x04\x83{\x08\x9d\nN\xaa+\x81\x07\x9e\xaa\xe2\x14\x9f.\xa7"
    b"\x9c,l\x16\xfe\x02!\x00\x81\x00wXq\rP\x1b\xcfL\xb2#\x8b\x9f\xeb"
    b"\xea\xa2\xd1\xc9\x12qA\x9e\xdd\xb1\x1cY8\xc3\xc7\xd6\xe8\x02!\x00"
    b"\xd3{!\xd3\x95\xeduc\x11\x18\x90\xf2\xc9\x84'+\xdei\xf1-\x86z\xb8"
    b"\xb6\x04\xae\xef\x02\x97pQ-\x02 X|\xbb\xba}\x92\xf8W\xacKTV\xed5"
    b"\xae~\x0c|\xc0v\x8fi\xfa\x01\x01\x16Rp\x9a\xafB\xd7\x02!\x00\xd8"
    b"\xfd\xbe\xc6\x1e;=\xd5\xde\x0b\xce\x01)\xfeQJ~\x13\xae\xf8\xbby"
    b"\xa6jB\x9b%\xff\xc1\xa7%\xc9\x02!\x00\xe7\xc7\x8b\x02\n|[\xed"
    b'\x0f:#\x97qM\x8e\xe6\xe8}\x8dMe@xA"\x9b\xbe\x81\x91\x86\xc0\xdf'
)
singature_repr = """RingSignature(
  curve.oid: 1.3.132.0.10
  hash.oid: 2.16.840.1.101.3.4.2.8
  c: 7caf9849b6dce78ea4c78a2c7ce8c64a8f62a92991d9e46b774f83c2f125ebd2
  s:[
     80e7c3865efe9f6cbe78dd46e23e574f4fcbf7b72e2cfcc820f27ef763c4b7a2
     da31c1cfaf44cea455eb32fbf7f4a8c9b0b1b152fb94f087571c602f93ff8da6
     d40deac948975f9c69c1df2bff67c44342a37c3264bcbfd5ccfe4d8998b15cc3
     0052d98ba7b0d046a85535c9d5ab8bce9d652d4dd30f4a478fba061989e04cbc
     2e9130e41c8ed6105604837b089d0a4eaa2b81079eaae2149f2ea79c2c6c16fe
     81007758710d501bcf4cb2238b9febeaa2d1c91271419eddb11c5938c3c7d6e8
     d37b21d395ed7563111890f2c984272bde69f12d867ab8b604aeef029770512d
     587cbbba7d92f857ac4b5456ed35ae7e0c7cc0768f69fa01011652709aaf42d7
     d8fdbec61e3b3dd5de0bce0129fe514a7e13aef8bb79a66a429b25ffc1a725c9
     e7c78b020a7c5bed0f3a2397714d8ee6e87d8d4d65407841229bbe819186c0df
  ]
  key_image:
     d20f899f3ca64fa7ad81d0621b6387d9f6dc97836ff2b54368e2507b096bcf01
     6be92d623ebcfc51b0bf1a626c7ec660106360518b34baf49e2b38f13ee6e139
)"""

signature_pem = b"""----- BEGIN RING-SIGNATURE -----
  Ring.type: LiuWeiWong
  Curve.oid: 1.3.132.0.10
   Hash.oid: 2.16.840.1.101.3.4.2.8
Key.image.x: 0xd20f899f3ca64fa7ad81d0621b6387d9f6dc97836ff2b54368e2507b096bcf01
Key.image.y: 0x6be92d623ebcfc51b0bf1a626c7ec660106360518b34baf49e2b38f13ee6e139

BApMaXVXZWlXb25nAgEBBgUrgQQACgYJYIZIAWUDBAIIMEUCIQDSD4mfPKZPp62B
0GIbY4fZ9tyXg2/ytUNo4lB7CWvPAQIga+ktYj68/FGwvxpibH7GYBBjYFGLNLr0
nis48T7m4TkCIHyvmEm23OeOpMeKLHzoxkqPYqkpkdnka3dPg8LxJevSMIIBWgIh
AIDnw4Ze/p9svnjdRuI+V09Py/e3Liz8yCDyfvdjxLeiAiEA2jHBz69EzqRV6zL7
9/SoybCxsVL7lPCHVxxgL5P/jaYCIQDUDerJSJdfnGnB3yv/Z8RDQqN8MmS8v9XM
/k2JmLFcwwIfUtmLp7DQRqhVNcnVq4vOnWUtTdMPSkePugYZieBMvAIgLpEw5ByO
1hBWBIN7CJ0KTqorgQeequIUny6nnCxsFv4CIQCBAHdYcQ1QG89MsiOLn+vqotHJ
EnFBnt2xHFk4w8fW6AIhANN7IdOV7XVjERiQ8smEJyveafEthnq4tgSu7wKXcFEt
AiBYfLu6fZL4V6xLVFbtNa5+DHzAdo9p+gEBFlJwmq9C1wIhANj9vsYeOz3V3gvO
ASn+UUp+E674u3mmakKbJf/BpyXJAiEA58eLAgp8W+0POiOXcU2O5uh9jU1lQHhB
Ipu+gZGGwN8=
----- END RING-SIGNATURE -----"""


class TestRignSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signature = RingSignature(
            (1, 3, 132, 0, 10),
            64,
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
            signature_c,
            signature_s,
            key_image,
        )

    def test_create_instance(self):
        self.assertEqual(str(self.signature), singature_repr)

    def test_to_der(self):
        content = self.signature.to_der()
        self.assertEqual(content, singature_der)

    def test_from_der(self):
        signature = signature_from_der(singature_der)
        self.assertEqual(str(self.signature), singature_repr)

    def test_to_pem(self):
        content = self.signature.to_pem()
        self.assertEqual(content, signature_pem)

    def test_from_pem(self):
        signature = signature_from_pem(signature_pem)
        self.assertEqual(str(self.signature), singature_repr)

    def test_seq_to_str(self):
        self.assertEqual(seq_to_str((1, 2, 3)), "1.2.3")

    def test_str_to_seq(self):
        self.assertEqual(str_to_seq("1.2.3"), (1, 2, 3))

    def test_read_der_tag(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x02\x01*")
        value = read_der_tag(decoder, asn1.Numbers.Integer, "Test")
        self.assertEqual(value, 42)

    def test_read_der_tag_error(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x02\x01*")
        with self.assertRaisesRegex(SignatureInvalidFormat, "Unexpected tag"):
            read_der_tag(decoder, asn1.Numbers.OctetString, "Unexpected tag")

    def test_read_der_int(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x02\x01*")
        self.assertEqual(read_der_int(decoder), 42)

    def test_read_der_int_error(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x04\x03foo")
        with self.assertRaisesRegex(SignatureInvalidFormat, "Unexpected int"):
            read_der_int(decoder, "Unexpected int")

    def test_read_der_oid(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x06\x02*\x03")
        self.assertEqual(read_der_oid(decoder), "1.2.3")

    def test_read_der_oid_error(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x04\x03foo")
        with self.assertRaisesRegex(SignatureInvalidFormat, "Unexpected oid"):
            read_der_oid(decoder, "Unexpected oid")

    def test_read_der_octet(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x04\x02ok")
        self.assertEqual(read_der_octet(decoder), b"ok")

    def test_read_der_octet_error(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x06\x02*\x03")
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "Unexpected octet"
        ):
            read_der_octet(decoder, "Unexpected octet")

    def test_peek_sequence(self):
        decoder = asn1.Decoder()
        decoder.start(b"0\x03\x02\x01*")
        peek_sequence(decoder, "Unexpected value")

    def test_peek_sequence_error(self):
        decoder = asn1.Decoder()
        decoder.start(b"\x06\x02*\x03")
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "Unexpected value"
        ):
            peek_sequence(decoder, "Unexpected value")

    def test_der_unsupported_type(self):
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "Unsupported type"
        ):
            signature_from_der(b"\x04\x03Foo")

    def test_der_unsupported_version(self):
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "Unsupported version"
        ):
            signature_from_der(b"\x04\nLiuWeiWong\x02\x01*")

    def test_der_unsupported_curve(self):
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "I don't know about the curve with oid"
        ):
            signature_from_der(b"\x04\nLiuWeiWong\x02\x01\x01\x06\x02*\x03")

    def test_der_unsupported_bash(self):
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "Unknown OID of hash function."
        ):
            signature_from_der(
                b"\x04\nLiuWeiWong\x02\x01\x01\x06\x05+\x81\x04\x00\n\x06\x02*\x03"
            )
