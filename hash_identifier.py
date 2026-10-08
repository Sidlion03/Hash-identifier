import argparse
import sys
from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.table import Table




"""working on classes on  how to identify hash """

Confidence = Literal['low','medium','high']

@dataclass(frozen = True,slots = True) #frozen makes it imutable and slots makes it lightweight on the memory
class HashCandidate:
    algorithm: str # what type of hash it is .
    confidence: Confidence # high : definitive prefix match , medium : length match only with one match , low : many reasons  .
    discrtiption:str # why did algoritm chose that hash.

"""we have to create rules or data so that we can dicern the different hashes"""

PREFIX_RULE:list[tuple[str,str,str]] = [
    # Argon2 family 
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bcrypt 
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd MD5 variant — same MD5 family as $1$ above but
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass 
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAPz
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),
]

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
"""using upper for MySQL5 hash cause they only produce upper chars"""
HEX_UPPER_SET : frozenset[str] = frozenset("0123456789ABCDEF")

"""making hex lenght rules"""

HEX_LENGHT_RULES: dict[int,list[str]] = {
    16: ["MySQL323", "CRC-64"],
        # 32 hex chars = 16 bytes = 128 bits
        32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
        # 40 hex chars = 20 bytes = 160 bits
        40: ["SHA-1", "RIPEMD-160"],
        # 48 hex chars = 24 bytes = 192 bits
        48: ["Tiger-192"],
        # 56 hex chars = 28 bytes = 224 bits
        56: ["SHA-224", "SHA3-224"],
        # 64 hex chars = 32 bytes = 256 bits
        64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
        # 80 hex chars = 40 bytes = 320 bits (uncommon)
        80: ["RIPEMD-320"],
        # 96 hex chars = 48 bytes = 384 bits
        96: ["SHA-384", "SHA3-384"],
        # 128 hex chars = 64 bytes = 512 bits
        128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

"""returns true if every charecter is a hex"""

def _is_hex(text : str)-> bool :
    return bool(text) and all(c in HEX_CHARSET for c in text)