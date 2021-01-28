try:
    import unittest2 as unittest
except ImportError:
    import unittest

import asn1

from .ring_signature import (
    RingSignature,
    SignatureInvalidFormat,
    peek_sequence,
    read_der_int,
    read_der_octet,
    read_der_oid,
    read_der_tag,
    seq_to_str,
    signature_from_der,
    signature_from_pem,
    str_to_seq,
)

signature_c = (
    0x8934A62D0EC1C4CD8E77A30D1FA9860291E1B512D1407898046193F86DC4316F
)
signature_s = [
    0x80E7C3865EFE9F6CBE78DD46E23E574F4FCBF7B72E2CFCC820F27EF763C4B7A2,
    0xDA31C1CFAF44CEA455EB32FBF7F4A8C9B0B1B152FB94F087571C602F93FF8DA6,
    0x897B47E29AB037B1DE3953B2D0997EFE2E757124604DC1CBB5DE1030414579B8,
    0x0052D98BA7B0D046A85535C9D5AB8BCE9D652D4DD30F4A478FBA061989E04CBC,
    0x2E9130E41C8ED6105604837B089D0A4EAA2B81079EAAE2149F2EA79C2C6C16FE,
    0x81007758710D501BCF4CB2238B9FEBEAA2D1C91271419EDDB11C5938C3C7D6E8,
    0xD37B21D395ED7563111890F2C984272BDE69F12D867AB8B604AEEF029770512D,
    0x587CBBBA7D92F857AC4B5456ED35AE7E0C7CC0768F69FA01011652709AAF42D7,
    0xD8FDBEC61E3B3DD5DE0BCE0129FE514A7E13AEF8BB79A66A429B25FFC1A725C9,
    0xE7C78B020A7C5BED0F3A2397714D8EE6E87D8D4D65407841229BBE819186C0DF,
]
key_image = (
    0xC38F72D1E01F8E303ADF7A7870F6863B280932520337CEF8231EA822A557C32D,
    0x0DB849041F31815B315A44677F3A3B0C8CB78164464DA11EE006F61448D366CE,
)
singature_der = (
    b"\x04\nLiuWeiWong\x02\x01\x01\x06\x05+\x81\x04\x00\n\x06\t`\x86H\x01e\x03"
    b"\x04\x02\x080E\x02!\x00\xc3\x8fr\xd1\xe0\x1f\x8e0:\xdfzxp\xf6\x86;(\t2R"
    b'\x037\xce\xf8#\x1e\xa8"\xa5W\xc3-\x02 \r\xb8I\x04\x1f1\x81[1ZDg\x7f:;'
    b"\x0c\x8c\xb7\x81dFM\xa1\x1e\xe0\x06\xf6\x14H\xd3f\xce\x02!\x00\x894\xa6-"
    b"\x0e\xc1\xc4\xcd\x8ew\xa3\r\x1f\xa9\x86\x02\x91\xe1\xb5\x12\xd1@x\x98"
    b"\x04a\x93\xf8m\xc41o\x02\x01\n0\x82\x01Z\x02!\x00\x80\xe7\xc3\x86^\xfe"
    b"\x9fl\xbex\xddF\xe2>WOO\xcb\xf7\xb7.,\xfc\xc8 \xf2~\xf7c\xc4\xb7\xa2"
    b"\x02!\x00\xda1\xc1\xcf\xafD\xce\xa4U\xeb2\xfb\xf7\xf4\xa8\xc9\xb0\xb1"
    b"\xb1R\xfb\x94\xf0\x87W\x1c`/\x93\xff\x8d\xa6\x02!\x00\x89{G\xe2\x9a\xb07"
    b"\xb1\xde9S\xb2\xd0\x99~\xfe.uq$`M\xc1\xcb\xb5\xde\x100AEy\xb8\x02\x1fR"
    b"\xd9\x8b\xa7\xb0\xd0F\xa8U5\xc9\xd5\xab\x8b\xce\x9de-M\xd3\x0fJG\x8f\xba"
    b"\x06\x19\x89\xe0L\xbc\x02 .\x910\xe4\x1c\x8e\xd6\x10V\x04\x83{\x08\x9d"
    b"\nN\xaa+\x81\x07\x9e\xaa\xe2\x14\x9f.\xa7\x9c,l\x16\xfe\x02!\x00\x81"
    b"\x00wXq\rP\x1b\xcfL\xb2#\x8b\x9f\xeb\xea\xa2\xd1\xc9\x12qA\x9e\xdd\xb1"
    b"\x1cY8\xc3\xc7\xd6\xe8\x02!\x00\xd3{!\xd3\x95\xeduc\x11\x18\x90\xf2\xc9"
    b"\x84'+\xdei\xf1-\x86z\xb8\xb6\x04\xae\xef\x02\x97pQ-\x02 X|\xbb\xba}"
    b"\x92\xf8W\xacKTV\xed5\xae~\x0c|\xc0v\x8fi\xfa\x01\x01\x16Rp\x9a\xafB\xd7"
    b"\x02!\x00\xd8\xfd\xbe\xc6\x1e;=\xd5\xde\x0b\xce\x01)\xfeQJ~\x13\xae\xf8"
    b"\xbby\xa6jB\x9b%\xff\xc1\xa7%\xc9\x02!\x00\xe7\xc7\x8b\x02\n|[\xed\x0f:#"
    b'\x97qM\x8e\xe6\xe8}\x8dMe@xA"\x9b\xbe\x81\x91\x86\xc0\xdf'
)
singature_repr = """RingSignature(
  curve.oid: 1.3.132.0.10
  hash.oid: 2.16.840.1.101.3.4.2.8
  c: 8934a62d0ec1c4cd8e77a30d1fa9860291e1b512d1407898046193f86dc4316f
  s:[
     80e7c3865efe9f6cbe78dd46e23e574f4fcbf7b72e2cfcc820f27ef763c4b7a2
     da31c1cfaf44cea455eb32fbf7f4a8c9b0b1b152fb94f087571c602f93ff8da6
     897b47e29ab037b1de3953b2d0997efe2e757124604dc1cbb5de1030414579b8
     0052d98ba7b0d046a85535c9d5ab8bce9d652d4dd30f4a478fba061989e04cbc
     2e9130e41c8ed6105604837b089d0a4eaa2b81079eaae2149f2ea79c2c6c16fe
     81007758710d501bcf4cb2238b9febeaa2d1c91271419eddb11c5938c3c7d6e8
     d37b21d395ed7563111890f2c984272bde69f12d867ab8b604aeef029770512d
     587cbbba7d92f857ac4b5456ed35ae7e0c7cc0768f69fa01011652709aaf42d7
     d8fdbec61e3b3dd5de0bce0129fe514a7e13aef8bb79a66a429b25ffc1a725c9
     e7c78b020a7c5bed0f3a2397714d8ee6e87d8d4d65407841229bbe819186c0df
  ]
  key_image:
     c38f72d1e01f8e303adf7a7870f6863b280932520337cef8231ea822a557c32d
     0db849041f31815b315a44677f3a3b0c8cb78164464da11ee006f61448d366ce
)"""

signature_pem = b"""----- BEGIN RING-SIGNATURE -----
  Ring.type: LiuWeiWong
  Curve.oid: 1.3.132.0.10
   Hash.oid: 2.16.840.1.101.3.4.2.8
Key.image.x: 0xc38f72d1e01f8e303adf7a7870f6863b280932520337cef8231ea822a557c32d
Key.image.y: 0x0db849041f31815b315a44677f3a3b0c8cb78164464da11ee006f61448d366ce

BApMaXVXZWlXb25nAgEBBgUrgQQACgYJYIZIAWUDBAIIMEUCIQDDj3LR4B+OMDrf
enhw9oY7KAkyUgM3zvgjHqgipVfDLQIgDbhJBB8xgVsxWkRnfzo7DIy3gWRGTaEe
4Ab2FEjTZs4CIQCJNKYtDsHEzY53ow0fqYYCkeG1EtFAeJgEYZP4bcQxbwIBCjCC
AVoCIQCA58OGXv6fbL543UbiPldPT8v3ty4s/Mgg8n73Y8S3ogIhANoxwc+vRM6k
Vesy+/f0qMmwsbFS+5Twh1ccYC+T/42mAiEAiXtH4pqwN7HeOVOy0Jl+/i51cSRg
TcHLtd4QMEFFebgCH1LZi6ew0EaoVTXJ1auLzp1lLU3TD0pHj7oGGYngTLwCIC6R
MOQcjtYQVgSDewidCk6qK4EHnqriFJ8up5wsbBb+AiEAgQB3WHENUBvPTLIji5/r
6qLRyRJxQZ7dsRxZOMPH1ugCIQDTeyHTle11YxEYkPLJhCcr3mnxLYZ6uLYEru8C
l3BRLQIgWHy7un2S+FesS1RW7TWufgx8wHaPafoBARZScJqvQtcCIQDY/b7GHjs9
1d4LzgEp/lFKfhOu+Lt5pmpCmyX/waclyQIhAOfHiwIKfFvtDzojl3FNjubofY1N
ZUB4QSKbvoGRhsDf
----- END RING-SIGNATURE -----"""

signature_pem_with_unexpected_data_at_the_end = b"""----- BEGIN RING-SIGNATURE -----
  Ring.type: LiuWeiWong
  Curve.oid: 1.3.132.0.10
   Hash.oid: 2.16.840.1.101.3.4.2.8
Key.image.x: 0xc38f72d1e01f8e303adf7a7870f6863b280932520337cef8231ea822a557c32d
Key.image.y: 0x0db849041f31815b315a44677f3a3b0c8cb78164464da11ee006f61448d366ce

BApMaXVXZWlXb25nAgEBBgUrgQQACgYJYIZIAWUDBAIIMEUCIQDDj3LR4B+OMDrf
enhw9oY7KAkyUgM3zvgjHqgipVfDLQIgDbhJBB8xgVsxWkRnfzo7DIy3gWRGTaEe
4Ab2FEjTZs4CIQCJNKYtDsHEzY53ow0fqYYCkeG1EtFAeJgEYZP4bcQxbwIBCjCC
AVoCIQCA58OGXv6fbL543UbiPldPT8v3ty4s/Mgg8n73Y8S3ogIhANoxwc+vRM6k
Vesy+/f0qMmwsbFS+5Twh1ccYC+T/42mAiEAiXtH4pqwN7HeOVOy0Jl+/i51cSRg
TcHLtd4QMEFFebgCH1LZi6ew0EaoVTXJ1auLzp1lLU3TD0pHj7oGGYngTLwCIC6R
MOQcjtYQVgSDewidCk6qK4EHnqriFJ8up5wsbBb+AiEAgQB3WHENUBvPTLIji5/r
6qLRyRJxQZ7dsRxZOMPH1ugCIQDTeyHTle11YxEYkPLJhCcr3mnxLYZ6uLYEru8C
l3BRLQIgWHy7un2S+FesS1RW7TWufgx8wHaPafoBARZScJqvQtcCIQDY/b7GHjs9
1d4LzgEp/lFKfhOu+Lt5pmpCmyX/waclyQIhAOfHiwIKfFvtDzojl3FNjubofY1N
ZUB4QSKbvoGRhsDfAgEK
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
        self.assertEqual(str(signature), singature_repr)

    def test_to_pem(self):
        content = self.signature.to_pem()
        self.assertEqual(content, signature_pem)

    def test_from_pem(self):
        signature = signature_from_pem(signature_pem)
        self.assertEqual(str(signature), singature_repr)

    def test_from_pem_with_unexpected_data_at_the_end(self):
        with self.assertRaisesRegex(
            SignatureInvalidFormat, "Unexpect tail data."
        ):
            signature_from_pem(signature_pem_with_unexpected_data_at_the_end)

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
