"""Hash scheme detection and verification.

Each :class:`HashScheme` knows how to *detect* whether an arbitrary string
looks like one of its hashes, and either:

* hash a plaintext deterministically (unsalted schemes), or
* verify a plaintext against a specific target hash (salted schemes).
"""
import hashlib
import re

from passlib.hash import (
    apr_md5_crypt,
    argon2,
    bcrypt,
    bcrypt_sha256,
    bsdi_crypt,
    bsd_nthash,
    cisco_pix,
    des_crypt,
    ldap_md5,
    ldap_salted_md5,
    ldap_salted_sha1,
    ldap_salted_sha256,
    ldap_salted_sha512,
    ldap_sha1,
    lmhash,
    md5_crypt,
    mssql2000,
    mysql323,
    mysql41,
    nthash,
    pbkdf2_sha1,
    pbkdf2_sha256,
    pbkdf2_sha512,
    phpass,
    sha1_crypt,
    sha256_crypt,
    sha512_crypt,
    sun_md5_crypt,
)


class HashScheme:
    def __init__(self, name, detect, salted, hash_fn=None, verify_fn=None):
        self.name = name
        self.detect = detect
        self.salted = salted
        self.hash_fn = hash_fn
        self.verify_fn = verify_fn

    def hash(self, plaintext):
        if self.hash_fn is None:
            raise ValueError(f"{self.name} is salted and cannot be hashed without a salt")
        return self.hash_fn(plaintext)

    def verify(self, plaintext, target):
        if self.verify_fn is None:
            raise ValueError(f"{self.name} is unsalted; compare hashes directly instead")
        return self.verify_fn(plaintext, target)

    def __repr__(self):
        return f"<HashScheme {self.name} salted={self.salted}>"


def _hex_detector(length):
    pattern = re.compile(rf"^[0-9a-fA-F]{{{length}}}$")
    return lambda h: bool(pattern.match(h))


def _make_raw(name, algo, length):
    def hash_fn(plaintext):
        return hashlib.new(algo, plaintext.encode("utf-8")).hexdigest().lower()
    return HashScheme(name, _hex_detector(length), salted=False, hash_fn=hash_fn)


def _make_passlib_unsalted(name, handler):
    def hash_fn(plaintext):
        return handler.hash(plaintext)
    return HashScheme(name, handler.identify, salted=False, hash_fn=hash_fn)


def _make_passlib_salted(name, handler):
    def verify_fn(plaintext, target):
        return handler.verify(plaintext, target)
    return HashScheme(name, handler.identify, salted=True, verify_fn=verify_fn)


SCHEMES = [
    _make_raw("md5", "md5", 32),
    _make_raw("sha1", "sha1", 40),
    _make_raw("sha224", "sha224", 56),
    _make_raw("sha3_224", "sha3_224", 56),
    _make_raw("sha256", "sha256", 64),
    _make_raw("sha3_256", "sha3_256", 64),
    _make_raw("blake2s", "blake2s", 64),
    _make_raw("sha384", "sha384", 96),
    _make_raw("sha3_384", "sha3_384", 96),
    _make_raw("sha512", "sha512", 128),
    _make_raw("sha3_512", "sha3_512", 128),
    _make_raw("blake2b", "blake2b", 128),
    _make_passlib_unsalted("ntlm", nthash),
    _make_passlib_unsalted("lm", lmhash),
    _make_passlib_unsalted("mysql323", mysql323),
    _make_passlib_unsalted("mysql41", mysql41),
    _make_passlib_unsalted("mssql2000", mssql2000),
    _make_passlib_unsalted("cisco_pix", cisco_pix),
    _make_passlib_unsalted("ldap_md5", ldap_md5),
    _make_passlib_unsalted("ldap_sha1", ldap_sha1),
    _make_passlib_salted("md5_crypt", md5_crypt),
    _make_passlib_salted("sha1_crypt", sha1_crypt),
    _make_passlib_salted("sha256_crypt", sha256_crypt),
    _make_passlib_salted("sha512_crypt", sha512_crypt),
    _make_passlib_salted("apr_md5_crypt", apr_md5_crypt),
    _make_passlib_salted("bcrypt", bcrypt),
    _make_passlib_salted("bcrypt_sha256", bcrypt_sha256),
    _make_passlib_salted("argon2", argon2),
    _make_passlib_salted("des_crypt", des_crypt),
    _make_passlib_salted("bsdi_crypt", bsdi_crypt),
    _make_passlib_salted("bsd_nthash", bsd_nthash),
    _make_passlib_salted("sun_md5_crypt", sun_md5_crypt),
    _make_passlib_salted("pbkdf2_sha1", pbkdf2_sha1),
    _make_passlib_salted("pbkdf2_sha256", pbkdf2_sha256),
    _make_passlib_salted("pbkdf2_sha512", pbkdf2_sha512),
    _make_passlib_salted("phpass", phpass),
    _make_passlib_salted("ldap_salted_md5", ldap_salted_md5),
    _make_passlib_salted("ldap_salted_sha1", ldap_salted_sha1),
    _make_passlib_salted("ldap_salted_sha256", ldap_salted_sha256),
    _make_passlib_salted("ldap_salted_sha512", ldap_salted_sha512),
]

_BY_NAME = {s.name: s for s in SCHEMES}

SCHEME_NAMES = frozenset(_BY_NAME)


def get_scheme(name):
    return _BY_NAME[name]


def detect_all(hash_str):
    """Return every scheme that could plausibly have produced ``hash_str``."""
    return [s for s in SCHEMES if s.detect(hash_str)]
