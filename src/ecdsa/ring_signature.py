# # Ring Signature.
# This signature is named ``LiuWeiWong`` after the authors Joseph K. Liu, Victor K. Wei and Duncan S. Wong.
import base64
import re
from typing import Sequence, Tuple, Union

import asn1

from .curves import UnknownCurveError, find_curve
from .hash_oid import UnknownOidError, get_hash_function


class RingSignature:
    """Ring Signature."""

    # Example of the signature dump:
    # ```
    # RingSignature(
    #   curve.oid: 1.3.132.0.10
    #   hash.oid: 2.16.840.1.101.3.4.2.8
    #   c: 7caf9849b6dce78ea4c78a2c7ce8c64a8f62a92991d9e46b774f83c2f125ebd2
    #   s:[
    #      80e7c3865efe9f6cbe78dd46e23e574f4fcbf7b72e2cfcc820f27ef763c4b7a2
    #      da31c1cfaf44cea455eb32fbf7f4a8c9b0b1b152fb94f087571c602f93ff8da6
    #      d40deac948975f9c69c1df2bff67c44342a37c3264bcbfd5ccfe4d8998b15cc3
    #      0052d98ba7b0d046a85535c9d5ab8bce9d652d4dd30f4a478fba061989e04cbc
    #      2e9130e41c8ed6105604837b089d0a4eaa2b81079eaae2149f2ea79c2c6c16fe
    #      81007758710d501bcf4cb2238b9febeaa2d1c91271419eddb11c5938c3c7d6e8
    #      d37b21d395ed7563111890f2c984272bde69f12d867ab8b604aeef029770512d
    #      587cbbba7d92f857ac4b5456ed35ae7e0c7cc0768f69fa01011652709aaf42d7
    #      d8fdbec61e3b3dd5de0bce0129fe514a7e13aef8bb79a66a429b25ffc1a725c9
    #      e7c78b020a7c5bed0f3a2397714d8ee6e87d8d4d65407841229bbe819186c0df
    #   ]
    #   key_image:
    #      d20f899f3ca64fa7ad81d0621b6387d9f6dc97836ff2b54368e2507b096bcf01
    #      6be92d623ebcfc51b0bf1a626c7ec660106360518b34baf49e2b38f13ee6e139
    # )
    # ```

    def __init__(
        self,
        curve_oid: Tuple[int],
        signature_length: int,
        hash_oid: Tuple[int],
        checksum: int,
        signatures: Sequence[int],
        key_image: Tuple[int],
    ):
        """Ring signature instance."""
        self.curve_oid = curve_oid
        self.signature_length = signature_length
        self.hash_oid = hash_oid
        self.checksum = checksum
        self.signatures = signatures
        self.key_image = key_image

    def __str__(self):
        """Ring signature instance representation."""
        hexpatt = "{{:0{}x}}".format(self.signature_length)
        patt = "\n".join(
            (
                "  curve.oid: {}",
                "  hash.oid: {}",
                "  c: " + hexpatt,
                "  s:[\n{}\n  ]",
                "  key_image:\n     " + hexpatt + "\n     " + hexpatt,
            )
        )
        spatt = "     " + hexpatt
        pattern = "RingSignature(\n" + patt + "\n)"
        return pattern.format(
            seq_to_str(self.curve_oid),
            seq_to_str(self.hash_oid),
            self.checksum,
            "\n".join([spatt.format(n) for n in self.signatures]),
            self.key_image[0],
            self.key_image[1],
        )

    def to_der(self) -> bytes:
        """Convert instance to format DER."""
        return signature_to_der(
            self.curve_oid,
            self.hash_oid,
            self.key_image,
            self.checksum,
            self.signatures,
        )

    def to_pem(self):
        """Convert instance to format PEM."""
        return signature_to_pem(
            self.curve_oid,
            self.hash_oid,
            self.key_image,
            self.checksum,
            self.signatures,
            self.signature_length,
        )


# # Import / Export

signature_type = "LiuWeiWong"
signature_version = 1


class SignatureInvalidFormat(Exception):
    """Signature invalid format."""


def seq_to_str(value: Sequence) -> str:
    """Convert sequence of int to str."""
    return ".".join(map(str, value))


def str_to_seq(value: str) -> Sequence:
    """Convert string to sequence of int."""
    return tuple(map(int, value.split(".")))


def read_der_tag(
    decoder: asn1.Decoder, tag_type: asn1.Numbers, message: str
) -> Union[int, str]:
    """Read integer from decoder."""
    tag, value = decoder.read()
    if tag.nr != tag_type:
        raise SignatureInvalidFormat(message)
    return value


def read_der_int(decoder: asn1.Decoder, message: str = "Int") -> int:
    """Read integer from decoder."""
    return read_der_tag(decoder, asn1.Numbers.Integer, message)


def read_der_oid(decoder: asn1.Decoder, message: str = "OID") -> str:
    """Read OID from decoder."""
    return read_der_tag(decoder, asn1.Numbers.ObjectIdentifier, message)


def read_der_octet(decoder: asn1.Decoder, message: str = "Octet") -> bytes:
    """Read octet string from decoder."""
    return read_der_tag(decoder, asn1.Numbers.OctetString, message)


def peek_sequence(decoder: asn1.Decoder, message: str = "Sequence"):
    """Peek sequence."""
    tag = decoder.peek()
    if tag.nr != asn1.Numbers.Sequence:
        raise SignatureInvalidFormat(message)


# ## Import / Export to DER
# ```
# RingSignature DEFINITIONS ::= BEGIN
#     Type       ::= OCTET STRING,
#     Version    ::= INTEGER,
#     CurveOID   ::= OBJECT IDENTIFIER,
#     HashOID    ::= OBJECT IDENTIFIER,
#     KeyImage   ::= SEQUENCE(SIZE(2)) OF INTEGER,
#     Checksum   ::= INTEGER,
#     Signatures ::= SEQUENCE OF INTEGER
# END
# ```


def signature_to_der(
    curve_oid: Tuple[int, ...],
    hash_oid: Tuple[int, ...],
    key_image: Tuple[int, int],
    checksum: int,
    signatures: Tuple[int, ...],
) -> bytes:
    """Convert instance to format DER."""
    encoder = asn1.Encoder()
    encoder.start()
    # Sign type
    encoder.write(signature_type.encode(), asn1.Numbers.OctetString)
    # Sign version
    encoder.write(signature_version, asn1.Numbers.Integer)
    # Curve OID
    encoder.write(seq_to_str(curve_oid), asn1.Numbers.ObjectIdentifier)
    # Hash OID
    encoder.write(seq_to_str(hash_oid), asn1.Numbers.ObjectIdentifier)
    # Key image
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(key_image[0], asn1.Numbers.Integer)
    encoder.write(key_image[1], asn1.Numbers.Integer)
    encoder.leave()
    # Checksum
    encoder.write(checksum, asn1.Numbers.Integer)
    # Signatures
    encoder.enter(asn1.Numbers.Sequence)
    for n in signatures:
        encoder.write(n, asn1.Numbers.Integer)
    encoder.leave()

    return encoder.output()


def signature_from_der(content: bytes) -> RingSignature:
    """Create RingSignature instance from format DER."""
    decoder = asn1.Decoder()
    decoder.start(content)
    # Signature type
    if read_der_octet(decoder, "Signature type") != signature_type.encode():
        raise SignatureInvalidFormat("Unsupported type")
    # Signature version
    if read_der_int(decoder, "Signature version") != signature_version:
        raise SignatureInvalidFormat("Unsupported version")
    # Curve type
    curve_oid = str_to_seq(read_der_oid(decoder, "Curve OID"))
    try:
        curve = find_curve(curve_oid)
    except UnknownCurveError as err:
        raise SignatureInvalidFormat(err)
    # Hash type
    hash_oid = str_to_seq(read_der_oid(decoder, "Hash OID"))
    try:
        get_hash_function(hash_oid)
    except UnknownOidError:
        raise SignatureInvalidFormat("Unknown OID of hash function.")
    # Key image
    peek_sequence(decoder, "Key image")
    decoder.enter()
    key_image = (read_der_int(decoder), read_der_int(decoder))
    decoder.leave()
    # Signature checksum
    checksum = read_der_int(decoder)
    # Sequence of signatures
    peek_sequence(decoder, "Signatures")
    signatures = []
    decoder.enter()
    while not decoder.eof():
        signatures.append(read_der_int(decoder))
    decoder.leave()
    return RingSignature(
        curve_oid,
        curve.signature_length,
        hash_oid,
        checksum,
        signatures,
        key_image,
    )


# ## Import / Export to PEM
#
# Example of PEM:
# ```
# ----- BEGIN RING-SIGNATURE -----
#   Ring.type: LiuWeiWong
#   Curve.oid: 1.3.132.0.10
#    Hash.oid: 2.16.840.1.101.3.4.2.8
# Key.image.x: 0xd20f899f3ca64fa7ad81d0621b6387d9f6dc97836ff2b54368e2507b096bcf01
# Key.image.y: 0x6be92d623ebcfc51b0bf1a626c7ec660106360518b34baf49e2b38f13ee6e139

# BApMaXVXZWlXb25nAgEBBgUrgQQACgYJYIZIAWUDBAIIMEUCIQDSD4mfPKZPp62B
# 0GIbY4fZ9tyXg2/ytUNo4lB7CWvPAQIga+ktYj68/FGwvxpibH7GYBBjYFGLNLr0
# nis48T7m4TkCIHyvmEm23OeOpMeKLHzoxkqPYqkpkdnka3dPg8LxJevSMIIBWgIh
# AIDnw4Ze/p9svnjdRuI+V09Py/e3Liz8yCDyfvdjxLeiAiEA2jHBz69EzqRV6zL7
# 9/SoybCxsVL7lPCHVxxgL5P/jaYCIQDUDerJSJdfnGnB3yv/Z8RDQqN8MmS8v9XM
# /k2JmLFcwwIfUtmLp7DQRqhVNcnVq4vOnWUtTdMPSkePugYZieBMvAIgLpEw5ByO
# 1hBWBIN7CJ0KTqorgQeequIUny6nnCxsFv4CIQCBAHdYcQ1QG89MsiOLn+vqotHJ
# EnFBnt2xHFk4w8fW6AIhANN7IdOV7XVjERiQ8smEJyveafEthnq4tgSu7wKXcFEt
# AiBYfLu6fZL4V6xLVFbtNa5+DHzAdo9p+gEBFlJwmq9C1wIhANj9vsYeOz3V3gvO
# ASn+UUp+E674u3mmakKbJf/BpyXJAiEA58eLAgp8W+0POiOXcU2O5uh9jU1lQHhB
# Ipu+gZGGwN8=
# ----- END RING-SIGNATURE -----
# ```


pem_name = "RING-SIGNATURE"


def signature_to_pem(
    curve_oid: Tuple[int, ...],
    hash_oid: Tuple[int, ...],
    key_image: Tuple[int, int],
    checksum: int,
    signatures: Tuple[int, ...],
    signature_length: int,
) -> bytes:
    """Convert instance to format PEM."""
    content = signature_to_der(
        curve_oid, hash_oid, key_image, checksum, signatures
    )
    b64 = base64.b64encode(content)
    columns = 64
    hexpatt = "{{:0{}x}}".format(signature_length)
    lines = ["----- BEGIN {} -----".format(pem_name).encode()]
    lines.append("  Ring.type: {}".format(signature_type).encode())
    lines.append("  Curve.oid: {}".format(seq_to_str(curve_oid)).encode())
    lines.append("   Hash.oid: {}".format(seq_to_str(hash_oid)).encode())
    lines.append(("Key.image.x: 0x" + hexpatt).format(key_image[0]).encode())
    lines.append(("Key.image.y: 0x" + hexpatt).format(key_image[1]).encode())
    lines.append(b"")
    lines.extend(
        [b64[start : start + columns] for start in range(0, len(b64), columns)]
    )
    lines.append("----- END {} -----".format(pem_name).encode())
    return b"\n".join(lines)


def signature_from_pem(content: bytes) -> RingSignature:
    """Create RingSignature instance from format PEM."""
    lines = []
    for line in content.decode().split("\n"):
        if not re.match(
            r"(\-\-\-|\s*(Ring\.type|Curve\.oid|Hash\.oid|Key\.image\.[xy]):)",
            line,
            re.IGNORECASE,
        ):
            lines.append(line)
    return signature_from_der(base64.b64decode("".join(lines)))
