# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

# Constants for IKEv2 RFC5996
# http://tools.ietf.org/html/rfc5996
from enum import IntEnum

import struct
from . util import dh

__author__ = 'kimvais'

IKE_VERSION = (2 << 4 | 0)  # Major << 4 | Minor

# iSPI, rSPI, NextPayload, (MjVer, MnVer), ExchangeType, Flags, MessageID, Len
IKE_HEADER = struct.Struct('!2Q4B2L')

class ExchangeType(IntEnum):
    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37

IKE_HDR_FLAGS = dict(
    R=0b00100000,
    I=0b00001000
)

PAYLOAD_HEADER = struct.Struct(
    '!2BH')  # Next Payload, Flags (Critical bit), Len

PROPOSAL_STRUCT = struct.Struct('!2BH4B')
# Last(0) or 2, Reserved, Proposal Length, Num, Protocol ID, SPI Size, Num transforms

TRANSFORM_STRUCT = struct.Struct('!2BH2BH')
# Last(0) or 3, Reserved, Transform Length, Transform type, Reserver, Transform ID

#    ENCR=1,  # Encryption (IKE and ESP)
#    PRF=2,   # Pseudo-random function (IKE)
#    INTEG=3, # Integrity (IKE, Optional for ESP (AH - not supported))
#    DH=4,    # Diffie-Hellman group
#    ESN=5,   # Extended sequence numbers.

TRANSFORMS = dict(
    AUTH_AES_XCBC_96=(3, 5),  # RFC 4307
    AUTH_HMAC_SHA1_96=(3, 2),  # RFC 4307
    AUTH_HMAC_SHA2_256_128=(3, 12),  # RFC 4868
    AUTH_HMAC_SHA2_384_192=(3, 13),  # RFC 4868
    AUTH_HMAC_SHA2_512_256=(3, 14),  # RFC 4868
    ENCR_AES_CBC=(1, 12),  # RFC 4307
    ENCR_AES_CTR=(1, 13),  # RFC 4307
    ENCR_CAMELLIA_CBC=(1, 23),  # RFC 5529
    ENCR_CAMELLIA_CTR=(1, 24),  # RFC 5529
    PRF_AES128_CBC=(2, 4),  # RFC 4307
    PRF_HMAC_SHA1=(2, 2),  # RFC 4307
    PRF_HMAC_SHA2_256=(2, 5),  # RFC 4868
    PRF_HMAC_SHA2_384=(2, 6),  # RFC 4868
    PRF_HMAC_SHA2_512=(2, 7),  # RFC 4868
    ESN=(5, 1)  # RFC 5996
)
for group_id in dh.PRIMES.keys():
    TRANSFORMS['DH_GROUP_{0:d}'.format(group_id)] = (4, group_id)

TRANFORM_ATTRIBUTES = struct.Struct('!2H')  # (0b10000000 | 14), Key Length

AUTH_MAC_SIZE = 32


class ProtocolID(IntEnum):
    IKE = 1
    AH = 2
    ESP = 3


class MessageType(IntEnum):
    Reserved = 0
    UNSUPPORTED_CRITICAL_PAYLOAD = 1
    INVALID_IKE_SPI = 4
    INVALID_MAJOR_VERSION = 5
    INVALID_SYNTAX = 7
    INVALID_MESSAGE_ID = 9
    INVALID_SPI = 11
    NO_PROPOSAL_CHOSEN = 14
    INVALID_KE_PAYLOAD = 17
    AUTHENTICATION_FAILED = 24
    SINGLE_PAIR_REQUIRED = 34
    NO_ADDITIONAL_SAS = 35
    INTERNAL_ADDRESS_FAILURE = 36
    FAILED_CP_REQUIRED = 37
    TS_UNACCEPTABLE = 38
    INVALID_SELECTORS = 39
    UNACCEPTABLE_ADDRESSES = 40
    UNEXPECTED_NAT_DETECTED = 41
    USE_ASSIGNED_HoA = 42
    TEMPORARY_FAILURE = 43
    CHILD_SA_NOT_FOUND = 44
    INVALID_GROUP_ID = 45
    AUTHORIZATION_FAILED = 46
    INITIAL_CONTACT = 16384
    SET_WINDOW_SIZE = 16385
    ADDITIONAL_TS_POSSIBLE = 16386
    IPCOMP_SUPPORTED = 16387
    NAT_DETECTION_SOURCE_IP = 16388
    NAT_DETECTION_DESTINATION_IP = 16389
    COOKIE = 16390
    USE_TRANSPORT_MODE = 16391
    HTTP_CERT_LOOKUP_SUPPORTED = 16392
    REKEY_SA = 16393
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394
    NON_FIRST_FRAGMENTS_ALSO = 16395
    MOBIKE_SUPPORTED = 16396
    ADDITIONAL_IP4_ADDRESS = 16397
    ADDITIONAL_IP6_ADDRESS = 16398
    NO_ADDITIONAL_ADDRESSES = 16399
    UPDATE_SA_ADDRESSES = 16400
    COOKIE2 = 16401
    NO_NATS_ALLOWED = 16402
    AUTH_LIFETIME = 16403
    MULTIPLE_AUTH_SUPPORTED = 16404
    ANOTHER_AUTH_FOLLOWS = 16405
    REDIRECT_SUPPORTED = 16406
    REDIRECT = 16407
    REDIRECTED_FROM = 16408
    TICKET_LT_OPAQUE = 16409
    TICKET_REQUEST = 16410
    TICKET_ACK = 16411
    TICKET_NACK = 16412
    TICKET_OPAQUE = 16413
    LINK_ID = 16414
    USE_WESP_MODE = 16415
    ROHC_SUPPORTED = 16416
    EAP_ONLY_AUTHENTICATION = 16417
    CHILDLESS_IKEV2_SUPPORTED = 16418
    QUICK_CRASH_DETECTION = 16419
    IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420
    IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421
    IKEV2_MESSAGE_ID_SYNC = 16422
    IPSEC_REPLAY_COUNTER_SYNC = 16423
    SECURE_PASSWORD_METHODS = 16424
    PSK_PERSIST = 16425
    PSK_CONFIRM = 16426
    ERX_SUPPORTED = 16427
    IFOM_CAPABILITY = 16428
    SENDER_REQUEST_ID = 16429

    def __repr__(self):
        return u"({0:s}: {1!r:s})".format(self._name_, self._value_)


class AuthenticationType(IntEnum):
    RSA = 1
    PSK = 2
    DSS = 3

AUTH_HEADER = "!B3x"
