try:
    import unittest2 as unittest
except ImportError:
    import unittest

import hashlib

from .hash_oid import (
    get_hash_function,
    get_oid_of_hash_function,
    UnknownOidError,
    UnknownHashFuncError,
)


class TestOidHash(unittest.TestCase):
    def test_oid_to_hash(self):
        self.assertEqual(get_hash_function((1, 3, 14, 3, 2, 26)), hashlib.sha1)
        self.assertEqual(
            get_hash_function((1, 2, 840, 113549, 2, 5)), hashlib.md5
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 2)), hashlib.sha384
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 3)), hashlib.sha512
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 4)), hashlib.sha224
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 7)),
            hashlib.sha3_224,
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 8)),
            hashlib.sha3_256,
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 9)),
            hashlib.sha3_384,
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 10)),
            hashlib.sha3_512,
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 11)),
            hashlib.shake_128,
        )
        self.assertEqual(
            get_hash_function((2, 16, 840, 1, 101, 3, 4, 2, 12)),
            hashlib.shake_256,
        )

    def test_hash_to_oid(self):
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha1), (1, 3, 14, 3, 2, 26)
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.md5), (1, 2, 840, 113549, 2, 5)
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha384),
            (2, 16, 840, 1, 101, 3, 4, 2, 2),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha512),
            (2, 16, 840, 1, 101, 3, 4, 2, 3),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha224),
            (2, 16, 840, 1, 101, 3, 4, 2, 4),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha3_224),
            (2, 16, 840, 1, 101, 3, 4, 2, 7),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha3_256),
            (2, 16, 840, 1, 101, 3, 4, 2, 8),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha3_384),
            (2, 16, 840, 1, 101, 3, 4, 2, 9),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.sha3_512),
            (2, 16, 840, 1, 101, 3, 4, 2, 10),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.shake_128),
            (2, 16, 840, 1, 101, 3, 4, 2, 11),
        )
        self.assertEqual(
            get_oid_of_hash_function(hashlib.shake_256),
            (2, 16, 840, 1, 101, 3, 4, 2, 12),
        )

    def test_unknown_oid_error(self):
        with self.assertRaises(UnknownOidError):
            get_hash_function((40, 41, 42))

    def test_unknown_hash_function_error(self):
        hashlib_fnc = lambda n: n
        with self.assertRaises(UnknownHashFuncError):
            get_oid_of_hash_function(hashlib_fnc)
