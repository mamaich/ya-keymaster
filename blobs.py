#!/usr/bin/env python3
'''
keymaster blob logic.

Offers:
 - low-level blob encoding and decoding
 - loading softkeymaster blobs
 - performing cryptographic operations (emulating KeyMaster) on a loaded blob
 - CLI tool for parsing softkeymaster blobs and performing operations with them

Still very limited on functionality, primarily for parsing.

(for forensics; not cryptographically secure)

based on:
 - system/keymaster @ 44ed723c4b4e
 - hardware/libhardware @ aed1b5671f6b
     - include/hardware/keymaster_defs.h
     - include/hardware/hw_auth_token.h
'''

from collections import defaultdict
from typing import Any, NamedTuple, Optional, BinaryIO, Callable, Tuple, Type, TypeVar, Union, get_args
from binascii import hexlify, unhexlify
from io import BytesIO
from struct import pack, unpack
from enum import Enum, unique
from dataclasses import dataclass
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes
from cryptography.hazmat.primitives import hashes, hmac, ciphers, padding
from datetime import datetime, timezone
import enum
import sys

def trim_docstring(text: str):
    if not text: return ''
    lines = text.expandtabs().splitlines()
    first, *lines = ( line.rstrip() for line in lines )
    # dedent all lines except the first
    calc_indent = lambda line: len(line) - len(line.lstrip())
    indent = min((calc_indent(line) for line in lines if line), default=0)
    lines = [ line[indent:] for line in lines ]
    # remove blank starting / ending lines
    trimmed = [ first.lstrip() ] + lines
    while trimmed and not trimmed[-1]: trimmed.pop()
    while trimmed and not trimmed[0]: trimmed.pop(0)
    return '\n'.join(trimmed)


# BASIC INFRASTRUCTURE
# --------------------

class DecodeError(Exception):
    pass

T = TypeVar('T')

def decode(x: bytes, fn: Callable[[BinaryIO], T]) -> T:
    st = BytesIO(x)
    result = fn(st)
    if excess := st.read():
        raise DecodeError(f'{len(excess)} excess bytes at end')
    return result

def encode(fn: Callable[[BinaryIO], None]) -> bytes:
    st = BytesIO()
    fn(st)
    return st.getvalue()

def read(st: BinaryIO, n: int):
    x = bytes()
    while n > 0:
        chunk = st.read(n)
        assert chunk != None
        if not chunk:
            raise DecodeError('unexpected EOF')
        x += chunk; n -= len(chunk)
    return x

def read_uint32(st: BinaryIO) -> int:
    return unpack('<L', read(st, 4))[0]

def write_uint32(x: int, st: BinaryIO):
    st.write(pack('<L', x))

def read_uint64(st: BinaryIO) -> int:
    return unpack('<Q', read(st, 8))[0]

def write_uint64(x: int, st: BinaryIO):
    st.write(pack('<Q', x))

def read_buffer(st: BinaryIO) -> bytes:
    return read(st, read_uint32(st))

def write_buffer(x: bytes, st: BinaryIO):
    write_uint32(len(x), st)
    st.write(x)


# COMMON DATA STRUCTURES (defined at the interface side)
# ----------------------
class enums:
    class Purpose(Enum):
        ENCRYPT = 0
        DECRYPT = 1
        SIGN = 2
        VERIFY = 3
        PURPOSE_4 = 4
        WRAP = 5
        AGREE_KEY = 6
        ATTEST_KEY = 7
    class Algorithm(Enum):
        RSA = 1
        EC = 3
        AES = 32
        TRIPLE_DES = 33
        HMAC = 128
    class BlockMode(Enum):
        ECB = 1
        CBC = 2
        CTR = 3
        GCM = 32
    class Digest(Enum):
        NONE = 0
        MD5 = 1
        SHA1 = 2
        SHA_2_224 = 3
        SHA_2_256 = 4
        SHA_2_384 = 5
        SHA_2_512 = 6
    class Padding(Enum):
        NONE = 1
        RSA_OAEP = 2
        RSA_PSS = 3
        RSA_PKCS1_1_5_ENCRYPT = 4
        RSA_PKCS1_1_5_SIGN = 5
        PKCS7 = 64
    class Kdf(Enum):
        KM_KDF_NONE = 0
        KM_KDF_RFC5869_SHA256 = 1
        KM_KDF_ISO18033_2_KDF1_SHA1 = 2
        KM_KDF_ISO18033_2_KDF1_SHA256 = 3
        KM_KDF_ISO18033_2_KDF2_SHA1 = 4
        KM_KDF_ISO18033_2_KDF2_SHA256 = 5
    class EcCurve(Enum):
        KM_EC_CURVE_P224 = 0
        KM_EC_CURVE_P256 = 1
        KM_EC_CURVE_P384 = 2
        KM_EC_CURVE_P521 = 3
        KM_EC_CURVE_25519 = 4
    class KeyBlobUsageRequirements(Enum):
        NONE = 0
    class AuthenticatorType(Enum):
        HW_AUTH_PASSWORD = 1
        HW_AUTH_BIOMETRIC = 2
    class KeyOrigin(Enum):
        KM_ORIGIN_GENERATED = 0
        KM_ORIGIN_DERIVED = 1
        KM_ORIGIN_IMPORTED = 2
        KM_ORIGIN_UNKNOWN = 3
        KM_ORIGIN_SECURELY_IMPORTED = 4

@unique
class TagType(Enum):
    repeating_base: Optional['TagType']
    def __init__(self, _):
        self.repeating_base = \
            self.__class__[self.name[:-4]] if self.name.endswith('_REP') else None

    ENUM = 1
    ENUM_REP = 2  # Repeatable enumeration value
    UINT = 3
    UINT_REP = 4  # Repeatable integer value
    ULONG = 5
    DATE = 6
    BOOL = 7
    BIGNUM = 8
    BYTES = 9
    ULONG_REP = 10  # Repeatable long value

TypeInfo = Tuple[TagType, Optional[Type[Enum]]]

class TagEnforceability(Enum):
    # Tags that must be semantically enforced by hardware and software implementations.
    ENFORCED = 1
    # Tags that should be semantically enforced by hardware if possible and will otherwise be
    # enforced by software (keystore).
    HARDWARE_ENFORCED = 2
    # Semantically unenforceable tags, either because they have no specific meaning or because
    # they're informational only.
    NONE = 3

@unique
class Tag(Enum):

    def __new__(cls, value, *kargs):
        obj = object.__new__(cls)
        obj._value_ = value
        return obj

    type: TypeInfo

    def __init__(self, _, type: Union[TagType, TypeInfo], docs=None):
        self.type = type if isinstance(type, tuple) else (type, None)
        self.tag = self.value | (self.type[0].value << 28)
        self.enforceability = \
            TagEnforceability.ENFORCED if self.value < 400 else \
            TagEnforceability.HARDWARE_ENFORCED if self.value < 700 else \
            TagEnforceability.NONE
        self.__doc__ = trim_docstring(docs)

    @classmethod
    def read(cls, st: BinaryIO):
        tag = read_uint32(st)
        try:
            self = cls(tag & ~(~0 << 28))
        except ValueError as exc:
            raise DecodeError() from exc
        if self.tag != tag:
            raise DecodeError('invalid tag type')
        return self

    def write(self, st: BinaryIO):
        st.write(self.tag)

    # Tags that must be semantically enforced by hardware and software implementations.

    ## Crypto parameters
    PURPOSE = 1, (TagType.ENUM_REP, enums.Purpose)
    ALGORITHM = 2, (TagType.ENUM, enums.Algorithm)
    KEY_SIZE = 3, TagType.UINT, '''Key size in bits.'''
    BLOCK_MODE = 4, (TagType.ENUM_REP, enums.BlockMode)
    DIGEST = 5, (TagType.ENUM_REP, enums.Digest)
    PADDING = 6, (TagType.ENUM_REP, enums.Padding)
    CALLER_NONCE = 7, TagType.BOOL, '''Allow caller to specify nonce or IV.'''
    MIN_MAC_LENGTH = 8, TagType.UINT, '''Minimum length of MAC or AEAD authentication tag in bits.'''
    KDF = 9, (TagType.ENUM_REP, enums.Kdf), '''(keymaster2)'''
    EC_CURVE = 10, (TagType.ENUM, enums.EcCurve), '''(keymaster2)'''
    ## Algorithm-specific.
    RSA_PUBLIC_EXPONENT = 200, TagType.ULONG
    ECIES_SINGLE_HASH_MODE = 201, TagType.BOOL, '''Whether the ephemeral public key is fed into the KDF'''
    INCLUDE_UNIQUE_ID = 202, TagType.BOOL, '''If true, attestation certificates for this key will contain an application-scoped and time-bounded device-unique ID. (keymaster2)'''
    RSA_OAEP_MGF_DIGEST = 203, (TagType.ENUM_REP, enums.Digest)
    # Other hardware-enforced.
    BLOB_USAGE_REQUIREMENTS = 301, (TagType.ENUM, enums.KeyBlobUsageRequirements)
    BOOTLOADER_ONLY = 302, TagType.BOOL, '''Usable only by bootloader'''
    ROLLBACK_RESISTANCE = 303, TagType.BOOL, '''Hardware enforced deletion with deleteKey or deleteAllKeys is supported'''
    EARLY_BOOT_ONLY = 305, TagType.BOOL, '''Key can only be used during early boot.'''

    # Tags that should be semantically enforced by hardware if possible and will otherwise be
    # enforced by software (keystore).

    ## Key validity period
    ACTIVE_DATETIME = 400, TagType.DATE, '''Start of validity'''
    ORIGINATION_EXPIRE_DATETIME = 401, TagType.DATE, '''Date when new "messages" should no longer be created.'''
    USAGE_EXPIRE_DATETIME = 402, TagType.DATE, '''Date when existing "messages" should no longer be trusted.'''
    MIN_SECONDS_BETWEEN_OPS = 403, TagType.UINT, '''Minimum elapsed time between cryptographic operations with the key.'''
    MAX_USES_PER_BOOT = 404, TagType.UINT, '''Number of times the key can be used per boot.'''
    USAGE_COUNT_LIMIT = 405, TagType.UINT, '''Number of cryptographic operations left with the key'''
    ## User authentication
    ALL_USERS = 500, TagType.BOOL, '''Reserved for future use -- ignore'''
    USER_ID = 501, TagType.UINT, '''Reserved for future use -- ignore'''
    USER_SECURE_ID = 502, TagType.ULONG_REP, \
        '''Secure ID of authorized user or authenticator(s).
        Disallowed if ALL_USERS or NO_AUTH_REQUIRED is present.'''
    NO_AUTH_REQUIRED = 503, TagType.BOOL, '''If key is usable without authentication.'''
    USER_AUTH_TYPE = 504, (TagType.ENUM, enums.AuthenticatorType), \
        '''Bitmask of authenticator types allowed when USER_SECURE_ID contains
        a secure user ID, rather than a secure authenticator ID.'''
    AUTH_TIMEOUT = 505, TagType.UINT, \
        '''Required freshness of user authentication for private/secret key
        operations, in seconds. Public key operations require no authentication.
        If absent, authentication is required for every use.
        Authentication state is lost when the device is powered off.'''
    ALLOW_WHILE_ON_BODY = 506, TagType.BOOL, \
        '''Allow key to be used after authentication timeout
        if device is still on-body (requires secure on-body sensor).'''
    TRUSTED_USER_PRESENCE_REQUIRED = 507, TagType.BOOL, '''Require test of user presence to use this key.'''
    TRUSTED_CONFIRMATION_REQUIRED = 508, TagType.BOOL, '''Require user confirmation through a trusted UI to use this key.'''
    UNLOCKED_DEVICE_REQUIRED = 509, TagType.BOOL, '''Require the device screen to be unlocked if the key is used.'''
    ## Application access control
    ALL_APPLICATIONS = 600, TagType.BOOL, '''Specified to indicate key is usable by all applications.'''
    APPLICATION_ID = 601, TagType.BYTES, '''Byte string identifying the authorized application.'''
    EXPORTABLE = 602, TagType.BOOL, \
        '''If true, private/secret key can be exported, but only
        if all access control requirements for use are met. (keymaster2)'''

    # Semantically unenforceable tags, either because they have no specific meaning or because
    # they're informational only.

    APPLICATION_DATA = 700, TagType.BYTES, '''Data provided by authorized application.'''
    CREATION_DATETIME = 701, TagType.DATE, '''Key creation time'''
    ORIGIN = 702, (TagType.ENUM, enums.KeyOrigin)
    ROLLBACK_RESISTANT = 703, TagType.BOOL, '''Whether key is rollback-resistant.'''
    ROOT_OF_TRUST = 704, TagType.BYTES, '''Root of trust ID.'''
    OS_VERSION = 705, TagType.UINT, '''Version of system (keymaster2)'''
    OS_PATCHLEVEL = 706, TagType.UINT, '''Patch level of system (keymaster2)'''
    UNIQUE_ID = 707, TagType.BYTES, '''Used to provide unique ID in attestation'''
    ATTESTATION_CHALLENGE = 708, TagType.BYTES, '''Used to provide challenge in attestation'''
    ATTESTATION_APPLICATION_ID = 709, TagType.BYTES, \
        '''Used to identify the set of possible applications of which
        one has initiated a key attestation'''
    ATTESTATION_ID_BRAND = 710, TagType.BYTES, '''Used to provide the device's brand name to be included in attestation'''
    ATTESTATION_ID_DEVICE = 711, TagType.BYTES, '''Used to provide the device's device name to be included in attestation'''
    ATTESTATION_ID_PRODUCT = 712, TagType.BYTES, '''Used to provide the device's product name to be included in attestation'''
    ATTESTATION_ID_SERIAL = 713, TagType.BYTES, '''Used to provide the device's serial number to be included in attestation'''
    ATTESTATION_ID_IMEI = 714, TagType.BYTES, '''Used to provide the device's IMEI to be included in attestation'''
    ATTESTATION_ID_MEID = 715, TagType.BYTES, '''Used to provide the device's MEID to be included in attestation'''
    ATTESTATION_ID_MANUFACTURER = 716, TagType.BYTES, '''Used to provide the device's manufacturer name to be included in attestation'''
    ATTESTATION_ID_MODEL = 717, TagType.BYTES, '''Used to provide the device's model name to be included in attestation'''
    VENDOR_PATCHLEVEL = 718, TagType.UINT, '''specifies the vendor image security patch level with which the key may be used'''
    BOOT_PATCHLEVEL = 719, TagType.UINT, '''specifies the boot image (kernel) security patch level with which the key may be used'''
    DEVICE_UNIQUE_ATTESTATION = 720, TagType.BOOL, '''Indicates StrongBox device-unique attestation is requested.'''
    IDENTITY_CREDENTIAL_KEY = 721, TagType.BOOL, '''This is an identity credential key'''
    STORAGE_KEY = 722, TagType.BOOL, '''storage encryption key'''
    ## Tags used only to provide data to or receive data from operations
    ASSOCIATED_DATA = 1000, TagType.BYTES, '''Used to provide associated data for AEAD modes.'''
    NONCE = 1001, TagType.BYTES, '''Nonce or Initialization Vector'''
    AUTH_TOKEN = 1002, TagType.BYTES, \
        '''Authentication token that proves secure user authentication has been performed.
        Structure defined in hw_auth_token_t in hw_auth_token.h.'''
    MAC_LENGTH = 1003, TagType.UINT, '''MAC or AEAD authentication tag length in bits.'''
    RESET_SINCE_ID_ROTATION = 1004, TagType.BOOL, \
        '''Whether the device has beeen factory reset since the last unique ID rotation.
        Used for key attestation.'''
    CONFIRMATION_TOKEN = 1005, TagType.BYTES, '''used to deliver a cryptographic token proving that the user confirmed a signing request.'''
    CERTIFICATE_SERIAL = 1006, TagType.BIGNUM, '''The serial number that should be set in the attestation certificate to be generated.'''
    CERTIFICATE_SUBJECT = 1007, TagType.BYTES, '''A DER-encoded X.500 subject that should be set in the attestation certificate to be generated.'''
    CERTIFICATE_NOT_BEFORE = 1008, TagType.DATE, \
        '''Epoch time in milliseconds of the start of the to be generated certificate's validity.
        The value should interpreted as too's complement signed integer.
        Negative values indicate dates before Jan 1970'''
    CERTIFICATE_NOT_AFTER = 1009, TagType.DATE, \
        '''Epoch time in milliseconds of the end of the to be generated certificate's validity.
        The value should interpreted as too's complement signed integer.
        Negative values indicate dates before Jan 1970'''
    MAX_BOOT_LEVEL = 1010, TagType.UINT, '''Specifies a maximum boot level at which a key should function.'''

class Param(NamedTuple):
    key: Tag
    value: Any

    def sort_key(self):
        '''sort key, according to keymaster_param_compare'''
        value = self.value
        # for enums, compare their values
        value = value.value if isinstance(value, Enum) else value
        if isinstance(value, list):
            value = [x.x if isinstance(x, Enum) else x for x in value]
        # FIXME: handle boolean, buffer / bignum
        # use the full tag number (including type)
        return self.key.tag, value

    def __ge__(self, other):
        return self.sort_key() >= other.sort_key() if self.__class__ is other.__class__ else None
    def __gt__(self, other):
        return self.sort_key() > other.sort_key() if self.__class__ is other.__class__ else None
    def __le__(self, other):
        return self.sort_key() <= other.sort_key() if self.__class__ is other.__class__ else None
    def __lt__(self, other):
        return self.sort_key() < other.sort_key() if self.__class__ is other.__class__ else None

    @staticmethod
    def read_value(st: BinaryIO, indirect_st: BinaryIO, tinfo: TypeInfo) -> Any:
        tag_type, enum = tinfo
        tag_type = tag_type.repeating_base or tag_type
        if tag_type == TagType.BOOL:
            x = read(st, 1)[0]
            if x > 1:
                raise DecodeError(f'invalid boolean {x}')
            return bool(x)
        if tag_type == TagType.ENUM:
            x = read_uint32(st)
            if enum:
                try:
                    x = enum(x)
                except ValueError as exc:
                    x = 0
                    #raise DecodeError('error matching enum field value') from exc
            return x
        if tag_type == TagType.UINT:
            return read_uint32(st)
        if tag_type == TagType.ULONG:
            return read_uint64(st)
        if tag_type == TagType.DATE:
            x = read_uint64(st)  # FIXME: negative?
            xp = x / 1000
            #assert int(xp * 1000) == x FIXME
            return datetime.fromtimestamp(xp, timezone.utc)
        if tag_type == TagType.BYTES or tag_type == TagType.BIGNUM:
            size = read_uint32(st)
            offset = read_uint32(st)
            if offset != indirect_st.tell():
                raise DecodeError(f'tag points to ${offset} but we are at {indirect_st.tell()}')
            x = read(indirect_st, size)
            # FIXME: for BIGNUM, convert to int
            return x
        raise AssertionError('should not happen')

    @staticmethod
    def write_value(value: Any, st: BinaryIO, indirect_st: BinaryIO, tinfo: TypeInfo) -> Any:
        tag_type, enum = tinfo
        tag_type = tag_type.repeating_base or tag_type
        if tag_type == TagType.BOOL:
            assert isinstance(value, bool)
            st.write(bytes([ int(value) ]))
            return
        if tag_type == TagType.ENUM:
            assert isinstance(value, enum) if enum else isinstance(value, int)
            write_uint32(value.value if enum else value, st)
            return
        if tag_type == TagType.UINT:
            assert isinstance(value, int)
            write_uint32(value, st)
            return
        if tag_type == TagType.ULONG:
            assert isinstance(value, int)
            write_uint64(value, st)
            return
        if tag_type == TagType.DATE:
            assert isinstance(value, datetime) and datetime.tzinfo == timezone.utc
            x = int(value.timestamp() * 1000)
            #assert x / 1000 == value.timestamp() FIXME
            write_uint64(x, st)
            return
        if tag_type == TagType.BYTES or tag_type == TagType.BIGNUM:
            # FIXME: for BIGNUM, convert from int
            assert isinstance(value, bytes)
            write_uint32(len(value), st)
            write_uint32(indirect_st.tell(), st)
            return
        raise AssertionError('should not happen')

    @classmethod
    def read(cls, st: BinaryIO, indirect_st: BinaryIO):
        tag = Tag.read(st)
        value = Param.read_value(st, indirect_st, tag.type)
        return cls(tag, value)

    def write(self, st: BinaryIO, indirect_st: BinaryIO):
        self.tag.write(st)
        Param.write_value(self.value, st, indirect_st, self.tag.type)

class AuthorizationSet(list[Param]):
    @classmethod
    def read(cls, st: BinaryIO):
        indirect_data = read_buffer(st)
        elements_count = read_uint32(st)
        elements_data = read_buffer(st)

        items = decode(indirect_data, lambda indirect_st:
            decode(elements_data, lambda st:
                [Param.read(st, indirect_st) for _ in range(elements_count)]))
        return cls(items)

    def write(self, st: BinaryIO):
        indirect_data = BytesIO()
        elements_data = BytesIO()
        for item in self:
            item.write(elements_data, indirect_data)
        write_buffer(indirect_data.getvalue())
        write_uint32(len(self))
        write_buffer(elements_data.getvalue())


# KEYMASTER BLOBS
# ---------------

@dataclass
class AuthEncryptedBlob:
    @unique
    class Format(Enum):
        AES_OCB = 0
        AES_GCM_WITH_SW_ENFORCED = 1
        AES_GCM_WITH_SECURE_DELETION = 2

        @classmethod
        def read(cls, st: BinaryIO):
            try:
                return cls(read(st, 1)[0])
            except ValueError as exc:
                raise DecodeError() from exc

        def write(self, st: BinaryIO):
            st.write(bytes([ self.value ]))

    @dataclass
    class EncryptedKey:
        class Format(Enum):
            AES_OCB = 0
            AES_GCM_WITH_SW_ENFORCED = 1
            AES_GCM_WITH_SECURE_DELETION = 2
        format: 'AuthEncryptedBlob.Format'
        nonce: bytes
        ciphertext: bytes
        tag: bytes

        def verify(self) -> bool:
            return len(self.nonce) == 12 and len(self.tag) == 16

        @classmethod
        def read(cls, st: BinaryIO):
            return cls(
                format = AuthEncryptedBlob.Format.read(st),
                nonce = read_buffer(st),
                ciphertext = read_buffer(st),
                tag = read_buffer(st),
            )

        def write(self, st: BinaryIO):
            self.format.write(st)
            write_buffer(self.nonce, st)
            write_buffer(self.ciphertext, st)
            write_buffer(self.tag, st)

        # FIXME: decrypt_key(), encrypt_key()

    key: EncryptedKey
    hw_enforced: AuthorizationSet
    sw_enforced: AuthorizationSet

    # uint32, only present for AES_GCM_WITH_SECURE_DELETION
    key_slot: Optional[int]

    def verify(self) -> bool:
        return self.key.verify() and \
            (self.key_slot != None) == (self.key.format == AuthEncryptedBlob.EncryptedKey.Format.AES_GCM_WITH_SECURE_DELETION)

    @classmethod
    def read(cls, st: BinaryIO):
        self = cls(
            key = AuthEncryptedBlob.EncryptedKey.read(st),
            hw_enforced = AuthorizationSet.read(st),
            sw_enforced = AuthorizationSet.read(st),
            key_slot = 0
        )

        if self.key.format == AuthEncryptedBlob.EncryptedKey.Format.AES_GCM_WITH_SECURE_DELETION:
            self.key_slot = read_uint32(st)

        return self

    def write(self, st: BinaryIO):
        self.key.write(st)
        self.hw_enforced.write(st)
        self.sw_enforced.write(st)

        if self.key.format == AuthEncryptedBlob.EncryptedKey.Format.AES_GCM_WITH_SECURE_DELETION:
            write_uint32(self.key_slot, st)

@dataclass
class IntegrityAssuredBlob:
    @dataclass
    class Inner:
        BLOB_VERSION = 0

        key: bytes
        hw_enforced: AuthorizationSet
        sw_enforced: AuthorizationSet

        def verify(self) -> bool:
            return True

        @classmethod
        def read(cls, st: BinaryIO):
            version = read(st, 1)[0]
            if version != IntegrityAssuredBlob.Inner.BLOB_VERSION:
                raise DecodeError(f'invalid version {version}')
            return cls(
                key = read_buffer(st),
                hw_enforced = AuthorizationSet.read(st),
                sw_enforced = AuthorizationSet.read(st),
            )

        def write(self, st: BinaryIO):
            st.write(bytes([ IntegrityAssuredBlob.Inner.BLOB_VERSION ]))
            write_buffer(self.key, st)
            self.hw_enforced.write(st)
            self.sw_enforced.write(st)

    HMAC_SIZE = 8
    HMAC_KEY = b'IntegrityAssuredBlob0'

    inner: Inner
    hmac: Optional[bytes]

    def verify(self) -> bool:
        return self.hmac and len(self.hmac) == IntegrityAssuredBlob.HMAC_SIZE

    def compute_hmac(self, hidden: AuthorizationSet) -> bytes:
        h = hmac.HMAC(IntegrityAssuredBlob.HMAC_KEY, hashes.SHA256)
        h.update(encode(self.inner.write))
        h.update(encode(hidden.write))
        return h.finalize()[:IntegrityAssuredBlob.HMAC_SIZE]

    def verify_hmac(self, hidden: AuthorizationSet) -> bytes:
        if self.hmac != (exp_hmac := self.compute_hmac(hidden)):
            raise ValueError(f'invalid HMAC (expected {hexlify(exp_hmac)}, got {hexlify(self.hmac)})')

    @classmethod
    def read(cls, st: BinaryIO):
        buf = st.read()
        if (ndata := len(buf) - IntegrityAssuredBlob.HMAC_SIZE) < 0:
            raise DecodeError('unexpected EOF')
        return cls(
            inner = decode(buf[:ndata], IntegrityAssuredBlob.Inner.read),
            hmac = buf[ndata:],
        )

    def write(self, st: BinaryIO):
        st.write(encode(self.inner.write))
        st.write(self.hmac)

@dataclass
class OldSoftkeymasterBlob:
    MAGIC = b'PK#8'

    # uint32, ignored
    type: int
    # ignored
    publicKey: bytes
    # PKCS#8 private key
    privateKey: bytes

    def verify(self) -> bool:
        return True

    # careful, this uses big endian

    @classmethod
    def read(cls, st: BinaryIO):
        if read(st, len(OldSoftkeymasterBlob.MAGIC)) != OldSoftkeymasterBlob.MAGIC:
            raise DecodeError(f'magic not matching')
        return cls(
            type = unpack('>I', read(st, 4))[0],
            publicKey = read(st, unpack('>I', read(st, 4))[0]),
            privateKey = read(st, unpack('>I', read(st, 4))[0]),
        )

    def write(self, st: BinaryIO):
        st.write(OldSoftkeymasterBlob.MAGIC)
        st.write(pack('>I', self.type))
        st.write(pack('>I', len(self.publicKey)))
        st.write(self.publicKey)
        st.write(pack('>I', len(self.privateKey)))
        st.write(self.privateKey)


# CRYPTOGRAPHIC OPERATIONS
# ------------------------

@dataclass
class LoadedBlob:
    '''A loaded and normalized blob, on which operations can be performed.'''

    key: bytes
    '''The material of the wrapped key'''

    hw_enforced: AuthorizationSet
    '''Hardware-enforced tags'''

    sw_enforced: AuthorizationSet
    '''Software-enforced tags'''

    def get_merged_tags(self) -> Tuple[ dict[Tag, list[Any]], Callable[[Tag, Optional[bool]], Optional[Any]] ]:
        tags = defaultdict(lambda: [])
        for tag, value in self.hw_enforced + self.sw_enforced:
            if value not in tags[tag]:
                tags[tag].append(value)

        def get_tag(tag: Tag, optional: Optional[bool]=False) -> Optional[Any]:
            ts = tags[tag]
            if len(ts) == 0 and (not optional):
                raise Exception(f'Tag {tag.name} not present in blob')
            if len(ts) > 1:
                print(f'WARNING: Tag {tag.name} has multiple values: {", ".join(map(str, ts))}\n' +
                        '         Picking first one.', file=sys.stderr)
            return next(iter(ts)) if ts else None

        return dict(tags), get_tag

    def initial_checks(self, purpose: enums.Purpose):
        '''Performs initial checks common to all operations.'''
        tags, get_tag = self.get_merged_tags()
        if tags[Tag.KEY_SIZE] and len(self.key) * 8 not in tags[Tag.KEY_SIZE]:
            print('WARNING: Key size does not match tags', file=sys.stderr)
        if purpose not in tags[Tag.PURPOSE]:
            print(f'WARNING: Key is not for {purpose.name} use', file=sys.stderr)

    def create_symmetric_cypher(self, iv: bytes) -> Tuple[ciphers.Cipher, Optional[padding.PKCS7]]:
        tags, get_tag = self.get_merged_tags()

        algs = cryptography.hazmat.primitives.ciphers.algorithms
        alg = {
            enums.Algorithm.AES: algs.AES,
            enums.Algorithm.TRIPLE_DES: algs.TripleDES,
        }[get_tag(Tag.ALGORITHM)](self.key)

        modes = cryptography.hazmat.primitives.ciphers.modes
        mode = {
            enums.BlockMode.ECB: modes.ECB,
            enums.BlockMode.CBC: modes.CBC,
            enums.BlockMode.CTR: modes.CTR,
            enums.BlockMode.GCM: modes.GCM,
        }[get_tag(Tag.BLOCK_MODE)]
        min_tag_length = get_tag(Tag.MIN_MAC_LENGTH)
        mode = mode(iv,
            **(dict(min_tag_length=min_tag_length//8) if min_tag_length != None else {}),
        )

        padder = {
            enums.Padding.NONE: None,
            enums.Padding.RSA_OAEP: False,
            enums.Padding.RSA_PSS: False,
            enums.Padding.RSA_PKCS1_1_5_ENCRYPT: False,
            enums.Padding.RSA_PKCS1_1_5_SIGN: False,
            enums.Padding.PKCS7: padding.PKCS7,
        }[get_tag(Tag.PADDING)]
        if padder is False:
            raise Exception('padding is not valid')
        padder = padder(alg.block_size) if padder else None

        return ciphers.Cipher(alg, mode), padder

    def decrypt(self, input: bytes, iv: bytes, tag: Optional[bytes] = None) -> bytes:
        '''Decrypts a message with the key blob.
        `tag` must be the authentication tag for AEAD ciphers or None otherwise'''
        tags, get_tag = self.get_merged_tags()
        self.initial_checks(enums.Purpose.DECRYPT)
        alg = get_tag(Tag.ALGORITHM)

        if alg in { enums.Algorithm.RSA, enums.Algorithm.EC }:
            # asymmetric crypto
            raise NotImplementedError('asymmetric crypto not implemented yet')
            curve = get_tag(Tag.EC_CURVE)

        if alg in { enums.Algorithm.AES, enums.Algorithm.TRIPLE_DES }:
            # symmetric crypto
            cipher, padder = self.create_symmetric_cypher(iv)
            has_tag = isinstance(cipher.mode, cryptography.hazmat.primitives.ciphers.modes.ModeWithAuthenticationTag)
            if has_tag != (tag != None):
                raise Exception(f'the chosen mode {"uses" if has_tag else "does not use"} an authentication tag')

            cipher = cipher.decryptor()
            input = cipher.update(input) + \
                (cipher.finalize_with_tag(tag) if has_tag else cipher.finalize())
            if padder:
                padder = padder.unpadder()
                input = padder.update(input) + padder.finalize()
            return input

        if alg == enums.Algorithm.HMAC:
            raise Exception('HMAC keys cannot be used for decryption')

        raise AssertionError('unreachable')

    def encrypt(self, input: bytes, iv: bytes) -> Tuple[bytes, Optional[bytes]]:
        '''Encrypts a message with the key blob.
        Returns (ciphertext, tag) where tag is the authentication tag for AEAD ciphers,
        or None otherwise.'''
        tags, get_tag = self.get_merged_tags()
        self.initial_checks(enums.Purpose.DECRYPT)
        alg = get_tag(Tag.ALGORITHM)

        if alg in { enums.Algorithm.RSA, enums.Algorithm.EC }:
            # asymmetric crypto
            raise NotImplementedError('asymmetric crypto not implemented yet')
            curve = get_tag(Tag.EC_CURVE)

        if alg in { enums.Algorithm.AES, enums.Algorithm.TRIPLE_DES }:
            # symmetric crypto
            cipher, padder = self.create_symmetric_cypher(iv)
            has_tag = isinstance(cipher.mode, cryptography.hazmat.primitives.ciphers.modes.ModeWithAuthenticationTag)

            if padder:
                padder = padder.padder()
                input = padder.update(input) + padder.finalize()
            cipher = cipher.encryptor()
            input = cipher.update(input) + cipher.finalize(input)
            return input, (cipher.tag if has_tag else None)

        if alg == enums.Algorithm.HMAC:
            raise Exception('HMAC keys cannot be used for encryption')

        raise AssertionError('unreachable')

    def sign(self, input: bytes) -> bytes:
        '''Signs a message using the key and returns the signature.'''
        tags, get_tag = self.get_merged_tags()
        self.initial_checks(enums.Purpose.DECRYPT)
        alg = get_tag(Tag.ALGORITHM)

        if alg in { enums.Algorithm.RSA, enums.Algorithm.EC }:
            raise NotImplementedError('asymmetric crypto not implemented yet')

        if alg in { enums.Algorithm.AES, enums.Algorithm.TRIPLE_DES }:
            raise Exception('symmetric crypto cannot be used for signing')

        if alg == enums.Algorithm.HMAC:
            digest = {
                enums.Digest.NONE: None, # FIXME
                enums.Digest.MD5: hashes.MD5,
                enums.Digest.SHA1: hashes.SHA1,
                enums.Digest.SHA_2_224: hashes.SHA224,
                enums.Digest.SHA_2_256: hashes.SHA256,
                enums.Digest.SHA_2_384: hashes.SHA384,
                enums.Digest.SHA_2_512: hashes.SHA512,
            }[get_tag(Tag.DIGEST)]()
            h = hmac.HMAC(self.key, digest)
            h.update(input)
            return h.finalize()

        raise AssertionError('unreachable')


# SOFTKEYMASTER LOGIC
# -------------------

# softkeymaster tries to decode blobs in this order:
SotfkeymasterBlob = Union[
    IntegrityAssuredBlob,
    AuthEncryptedBlob,
    OldSoftkeymasterBlob,
]

def decode_softkeymaster_blob(x: bytes) -> SotfkeymasterBlob:
    for handler in get_args(SotfkeymasterBlob):
        try:
            return decode(x, handler.read)
        except DecodeError:
            pass
    raise DecodeError('invalid blob')

def load_software_blob(blob: SotfkeymasterBlob) -> LoadedBlob:
    if isinstance(blob, IntegrityAssuredBlob):
        return LoadedBlob(blob.inner.key, blob.inner.hw_enforced, blob.inner.sw_enforced)
    if isinstance(blob, AuthEncryptedBlob):
        raise NotImplementedError('obtaining key material from AuthEncryptedBlob not implemented yet')
        return LoadedBlob(key, blob.hw_enforced, blob.sw_enforced)
    if isinstance(blob, OldSoftkeymasterBlob):
        raise NotImplementedError('deducing tags from OldSoftkeymasterBlob not implemented yet')
        inferred_tags = AuthorizationSet()
        return LoadedBlob(blob.privateKey, AuthorizationSet(), inferred_tags)
    raise AssertionError('should not happen')

# I'm too lazy to look up where exactly this header comes from,
# but it is probably tucked by the keystore interface to signal
# that the blob is a keymaster blob. what was keystore again?
KEYSTORE_MAGIC = b'pKMblob\0'

def print_blob(blob: SotfkeymasterBlob):

    print()
    print('BLOB TYPE:', {
        IntegrityAssuredBlob: '\x1b[1mIntegrityAssuredBlob\x1b[m (new keymaster1 software key blob, or new keymaster0-backed blob)',
        AuthEncryptedBlob: '\x1b[1mAuthEncryptedBlob\x1b[m (old keymaster1 software key blobs)',
        OldSoftkeymasterBlob: '\x1b[1mOldSoftkeymasterBlob\x1b[m (old keymaster0 software key blobs)',
    }[type(blob)])
    print()

    def print_auth_set(x: AuthorizationSet):
        fmt_os_version = lambda x: f'{x} (Android {x//10000}.{(x//10) % 10}{f".{x % 10}" if x % 10 else ""})'
        fmt_value = lambda tag, value: \
            value.isoformat(' ') if isinstance(value, datetime) else \
            fmt_os_version(value) if tag == Tag.OS_VERSION else \
            str(value)
        print('  [Empty]' if not x else '\n'.join(
            f'  - \x1b[32m{key.name}\x1b[m ({key.value}, {key.type[0].name}) = \x1b[33m{fmt_value(key, value)}\x1b[m' for key, value in x))

    if isinstance(blob, IntegrityAssuredBlob):
        inner = blob.inner
        print(f'Key ({len(inner.key)} bytes): \x1b[1m{hexlify(inner.key).decode()}\x1b[m')
        print()
        print('Hardware-enforced tags:')
        print_auth_set(inner.hw_enforced)
        print()
        print('Software-enforced tags:')
        print_auth_set(inner.sw_enforced)
        print()
        print('HMAC:', hexlify(blob.hmac).decode())
        # FIXME: HMAC checking not fully implemented yet
    if isinstance(blob, AuthEncryptedBlob):
        key = blob.key
        print('Encrypted key:')
        print(f'  Ciphertext: \x1b[1m{hexlify(key.ciphertext).decode()}\x1b[m')
        print(f'  Format    : \x1b[1m{key.format}\x1b[m')
        print(f'  Nonce / IV: \x1b[1m{hexlify(key.nonce).decode()}\x1b[m')
        print(f'  Tag: \x1b[1m{hexlify(key.tag).decode()}\x1b[m')
        print('(FIXME: the key is encrypted with an all-zeros\n  master key, but decryption is not implemented yet)')
        print()
        print('Hardware-enforced tags:')
        print_auth_set(blob.hw_enforced)
        print()
        print('Software-enforced tags:')
        print_auth_set(blob.sw_enforced)
        if blob.key_slot != None:
            print(f'\nKey slot: {blob.key_slot}')
    if isinstance(blob, OldSoftkeymasterBlob):
        print(f'Type: {blob.type}')
        print()
        print(f'Public key: {hexlify(blob.publicKey).decode()}')
        print()
        print(f'Key ({len(blob.privateKey)} bytes): \x1b[1m{hexlify(blob.privateKey).decode()}\x1b[m')
    print()

if __name__ == '__main__':
    import argparse

    blob_types = {
        'IntegrityAssured': IntegrityAssuredBlob,
        'AuthEncrypted': AuthEncryptedBlob,
        'OldSoftkeymaster': OldSoftkeymasterBlob,
    }

    parser = argparse.ArgumentParser(
        usage='blobs.py [-h] [options] BLOB_FILE',
        description='Parses key blobs from software KeyMaster implementations.')
    parser.add_argument('blob_file', metavar='BLOB_FILE',
                        help='file containing the blob to parse')
    parser.add_argument('--strict', metavar='INPUT_FILE', action=argparse.BooleanOptionalAction,
                        help="don't try to remove non-keymaster wrapping such as the keystore header")
    parser.add_argument('-t', '--type', metavar='BLOB_TYPE', choices=blob_types,
                        help=f'force a specific blob type to be parsed ({", ".join(blob_types)})')
    subparsers = parser.add_subparsers(dest='operation', help='instead of inspecting the blob, use it to perform an operation')
    parser_sign = subparsers.add_parser('sign', help='sign INPUT_FILE and output the signature to stdout')
    parser_sign.add_argument('input_file', metavar='INPUT_FILE')
    parser_decrypt = subparsers.add_parser('decrypt', help='decrypt INPUT_FILE and output the plaintext to stdout')
    parser_decrypt.add_argument('input_file', metavar='INPUT_FILE')
    parser_decrypt.add_argument('iv', metavar='IV', help='decryption IV, in hex')
    parser_decrypt.add_argument('auth_tag', metavar='AUTH_TAG', help='authentication tag, in hex')
    args = parser.parse_args()

    with open(args.blob_file, 'rb') as f:
        raw_blob = f.read()

    if (not args.strict) and raw_blob.startswith(KEYSTORE_MAGIC):
        raw_blob = raw_blob[len(KEYSTORE_MAGIC):]

    if args.type:
        blob = decode(raw_blob, blob_types[args.type].read)
    else:
        blob = decode_softkeymaster_blob(raw_blob)

    if args.operation:
        loaded_blob = load_software_blob(blob)
        with open(args.input_file, 'rb') as f:
            input = f.read()
        output = {
            'sign': lambda: loaded_blob.sign(input),
            'decrypt': lambda: loaded_blob.decrypt(input, unhexlify(args.iv),
                unhexlify(args.auth_tag) if args.auth_tag != None else None),
            # 'encrypt': lambda: loaded_blob.encrypt(input, unhexlify(args.iv)),
        }[args.operation]()
        sys.stdout.write(output)
    else:
        print_blob(blob)
