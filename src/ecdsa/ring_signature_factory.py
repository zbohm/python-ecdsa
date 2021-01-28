# Provide an implementation of Linkable Spontaneus Anonymous Group Signature
# over elliptic curve cryptography.
#
# Implementation of cryptographic scheme from PDF [Linkable Spontaneous Anonymous Group Signature
# for Ad Hoc Groups](https://eprint.iacr.org/2004/027.pdf) from Joseph K. Liu, Victor K. Wei and Duncan S. Wong.
#
# The code of ``sign`` and ``verify`` was taken from the project
# [ecc_linkable_ring_signatures](https://github.com/fernandolobato/ecc_linkable_ring_signatures) written by
# Fernanddo Lobato Meeser.
#
# Note: To show as a literar code documentation compile this code by [pycoo](https://pypi.org/project/Pycco/):
# ```
# $ pycco src/ecdsa/ring_signature_factory.py
# $ firefox docs/ring_signature_factory.html
# ```

# ### Example of usage:
# ```python
# import hashlib
#
# from ecdsa.curves import SECP256k1
# from ecdsa.ecdsa import Private_key, Public_key
# from ecdsa.ring_signature import signature_from_pem
# from ecdsa.ring_signature_factory import (
#     RingSignatureFactory,
#     get_ring_signature_factory
# )
# from ecdsa.util import randrange
#
# curve = SECP256k1
# g = curve.generator
# n = g.order()
#
# number_participants = 10
# my_private_key_position = 2
#
# # Generate private and public keys:
# private_keys, public_keys = [], []
#
# for i in range(number_participants):
#     secret = randrange(n)
#     pubkey = Public_key(g, g * secret)
#     privkey = Private_key(pubkey, secret)
#     public_keys.append(pubkey)
#     private_keys.append(privkey)
#
# message = b"Life, the Universe and Everything."
#
# # Make signature:
# factory = RingSignatureFactory(curve, hashlib.sha3_256)
# signature = factory.sign(
#     message,
#     private_keys[my_private_key_position],
#     public_keys,
#     my_private_key_position,
# )
#
# # Export to PEM:
# pem = signature.to_pem()
# print(pem.decode())
#
# # Import from PEM:
# sig = signature_from_pem(pem)
#
# # Verify signature:
# factory2 = get_ring_signature_factory(sig)
# if factory2.verify(message, sig, public_keys):
#     print("OK. Signature is valid.")
# else:
#     print("Error. Invalid signature.")
# ```

from typing import Callable, Sequence

from .curves import Curve, find_curve
from .ecdsa import Private_key, Public_key
from .ellipticcurve import Point
from .hash_oid import get_hash_function, get_oid_of_hash_function
from .ring_signature import RingSignature
from .util import randrange


class RingSignatureFactory:
    """Make ring signature and verify them."""

    def __init__(self, curve: Curve, hash_fnc: Callable[[bytes], object]):
        """Ring signature factory instance. Can raise UnknownHashFuncError."""
        self.curve = curve
        self.hash_fnc = hash_fnc
        self.hash_oid = get_oid_of_hash_function(hash_fnc)
        self.buffer_size = (self.curve.order.bit_length() + 7) // 8

    def hash_data(
        self,
        public_keys_digest: bytes,
        private_image: Point,
        message: bytes,
        gsi_yici: Point,
        hsi_yci: Point,
    ) -> int:
        """Make hash digest from input params. This is H1 in schema."""
        concacted = b"".join(
            (
                public_keys_digest,
                self.concat_point_coordinates(private_image),
                self.concat_point_coordinates(gsi_yici),
                self.concat_point_coordinates(hsi_yci),
                self.hash_fnc(message).digest(),
            )
        )
        return int(self.hash_fnc(concacted).hexdigest(), 16)

    def concat_point_coordinates(self, point: Point) -> bytes:
        """Return bytes of point coordinates x,y."""
        return point.x().to_bytes(
            self.buffer_size, "big"
        ) + point.y().to_bytes(self.buffer_size, "big")

    def public_keys_to_bytes(self, public_keys: Sequence[Point]) -> bytes:
        """Return bytes of point coordinates x,y from public keys sequence."""
        return b"".join(
            [self.concat_point_coordinates(point) for point in public_keys]
        )

    def public_keys_to_point(
        self, public_keys: Sequence[Point], case_id: bytes
    ) -> Point:
        """Hash public keys into Point. This is H2 in schema."""
        buff = self.public_keys_to_bytes(public_keys)
        digest = int.from_bytes(self.hash_fnc(buff + case_id).digest(), "big")
        return self.curve.generator * digest

    def sign(
        self,
        message: bytes,
        private_key: Private_key,
        public_keys: Sequence[Public_key],
        private_key_position: int,
        case_id: bytes = b"",
    ) -> RingSignature:
        """Make ring signature."""
        # # 4 A LSAG Signature Scheme

        # Let *G* = ⧼g⧽ be a group of prime order *q* such that the underlying discrete
        # logarithm problem is intractable. Let *H<sub>1</sub>* : {0, 1}∗ → *Z<sub>q</sub>* and
        # *H<sub>2</sub>* : {0, 1}∗ → *G* be some statistically independent cryptographic hash functions.
        # For *i = 1, · · ·, n,* each user *i* has a distinct public key *y<sub>i</sub>*
        # and a private key *x<sub>i</sub>* such that *y<sub>i</sub> = g<sup>x<sub>i</sub></sup>*.
        # Let *L = {y<sub>1</sub>, · · ·, y<sub>n</sub>}* be the list of *n* public keys.

        m = message
        xπ = private_key.secret_multiplier
        π = private_key_position
        L = [pubkey.point for pubkey in public_keys]

        q = self.curve.order
        G = self.curve.generator
        H1 = self.hash_data
        H2 = self.public_keys_to_point

        # ## 4.1 Signature Generation

        # Given message *m* ∈ {0, 1}∗, list of public key *L = {y<sub>1</sub>, · · · , y<sub>n</sub>}*, private key
        # x<sub>π</sub> corresponding to *y<sub>π</sub> 1 ≤ π ≤ n*, the following algorithm generates a LSAG
        # signature.

        n = len(L)
        c = [0] * n
        s = [0] * n

        # ### Step 1
        # Compute *h = H<sub>2</sub>(L)* and *ỹ = h<sup>x<sub>π</sub></sup>*.

        h = H2(L, case_id)
        y = h * xπ
        Lb = self.public_keys_to_bytes(L)  # Precomputed digest of public keys.

        # ### Step 2
        # Pick *u ∈<sub>R</sub> Z<sub>q</sub>*, and compute
        #
        # *c<sub>π+1</sub> = H<sub>1</sub>(L, ỹ, m, g<sup>u</sup>, h<sup>u</sup>)*.

        u = randrange(q)
        c[(π + 1) % n] = H1(Lb, y, m, G * u, h * u)

        # ### Step 3
        # For *i* = π+1, · · · , *n*, 1, · · · , π−1, pick *s<sub>i</sub> ∈<sub>R</sub> Z<sub>q</sub>* and compute
        #
        # *c<sub>i+1</sub> = H<sub>1</sub>(L, ỹ, m, g<sup>s<sub>i</sub></sup> y<sub>i</sub><sup>c<sub>i</sub></sup>,
        # h<sup>s<sub>i</sub></sup> ỹ<sup>c<sub>i</sub></sup>)*.

        for i in [i for i in range(π + 1, n)] + [i for i in range(π)]:
            s[i] = randrange(q)
            c[(i + 1) % n] = H1(
                Lb, y, m, (G * s[i]) + (L[i] * c[i]), (h * s[i]) + (y * c[i])
            )

        # ### Step 4
        # Compute *s<sub>π</sub>* = *u − x<sub>π</sub>c<sub>π</sub>* mod *q*.

        s[π] = (u - xπ * c[π]) % q

        # The signature is *σ<sub>L</sub>(m) = (c<sub>1</sub>, s<sub>1</sub> , · · ·, s<sub>n</sub>, ỹ)*.

        return RingSignature(
            self.curve.oid,
            self.curve.signature_length,
            self.hash_oid,
            c[0],
            s,
            (y.x(), y.y()),
        )

    def verify(
        self,
        message: bytes,
        signature: RingSignature,
        public_keys: Sequence[Public_key],
        case_id: bytes = b"",
    ) -> bool:
        """Verify ring signature."""
        # # 4.2 Signature Verification
        # A public verifier checks a signature *σ<sub>L</sub>(m) = (c<sub>1</sub>, s<sub>1</sub>, · · ·, s<sub>n</sub>,
        # ỹ)* on a message *m*  and a list of public keys *L* as follows.

        H1 = self.hash_data
        H2 = self.public_keys_to_point
        G = self.curve.generator

        m = message
        n = len(public_keys)
        c = [signature.checksum] + [0] * (n - 1)
        L = [pubkey.point for pubkey in public_keys]
        s = signature.signatures

        if len(signature.signatures) != n:
            return False
        try:
            y = Point(
                self.curve.curve,
                signature.key_image[0],
                signature.key_image[1],
            )
        except AssertionError:
            return False

        # ### Step 1
        # Compute *h = H<sub>2</sub>(L)* and for *i = 1, · · · , n,* compute
        # z'<sub>i</sub> = g<sup>s<sub>i</sub></sup> y<sub>i</sub><sup>c<sub>i</sub></sup>,<br>
        # z<sub>i</sub>'' = h<sup>s<sub>i</sub></sup> ỹ<sup>c<sub>i</sub></sup>
        # and then *c<sub>i+1</sub> = H<sub>1</sub>(L, ỹ, m, z<sub>i</sub>', z<sub>i</sub>'')* if *i ≠ n*.

        h = H2(L, case_id)
        Lb = self.public_keys_to_bytes(L)  # Precomputed digest of public keys.

        for i in range(n):
            z1 = (G * s[i]) + (L[i] * c[i])
            z2 = (h * s[i]) + (y * c[i])

            # ### Step 2.
            # Check whether *c<sub>1</sub> = H<sub>1</sub>(L, ỹ, m, z<sub>n</sub>', z<sub>n</sub>'')*.
            # If yes, accept. Otherwise, reject.
            if i < n - 1:
                c[i + 1] = H1(Lb, y, m, z1, z2)
            else:
                return signature.checksum == H1(Lb, y, m, z1, z2)

        return False


def get_ring_signature_factory(
    signature: RingSignature
) -> RingSignatureFactory:
    """Find used curve by curve OID and hash function from hashlib. Return RingSignatureFactory.

    Can raise UnknownCurveError or UnknownOidError.
    """
    curve = find_curve(signature.curve_oid)
    hash_func = get_hash_function(signature.hash_oid)
    return RingSignatureFactory(curve, hash_func)
