import hashlib
from typing import Callable, Tuple

# http://oidref.com/2.16.840.1.101.3.4.2.1
OID_HASH = {
    (1, 3, 14, 3, 2, 26): hashlib.sha1,
    (1, 2, 840, 113549, 2, 5): hashlib.md5,
    (2, 16, 840, 1, 101, 3, 4, 2, 2): hashlib.sha384,
    (2, 16, 840, 1, 101, 3, 4, 2, 3): hashlib.sha512,
    (2, 16, 840, 1, 101, 3, 4, 2, 4): hashlib.sha224,
    (2, 16, 840, 1, 101, 3, 4, 2, 7): hashlib.sha3_224,
    (2, 16, 840, 1, 101, 3, 4, 2, 8): hashlib.sha3_256,
    (2, 16, 840, 1, 101, 3, 4, 2, 9): hashlib.sha3_384,
    (2, 16, 840, 1, 101, 3, 4, 2, 10): hashlib.sha3_512,
    (2, 16, 840, 1, 101, 3, 4, 2, 11): hashlib.shake_128,
    (2, 16, 840, 1, 101, 3, 4, 2, 12): hashlib.shake_256,
}
HASH_OID = {fnc: oid for oid, fnc in OID_HASH.items()}


class UnknownOidError(Exception):
    """Unknown OID error."""


class UnknownHashFuncError(Exception):
    """Unknown hash function error."""


def get_hash_function(oid: Tuple[int, ...]) -> Callable:
    """Return hash function from hashlib."""
    try:
        return OID_HASH[oid]
    except KeyError:
        raise UnknownOidError()


def get_oid_of_hash_function(func: Callable) -> Tuple[int, ...]:
    """Return OID of hash function from hashlib."""
    try:
        return HASH_OID[func]
    except KeyError:
        raise UnknownHashFuncError()
