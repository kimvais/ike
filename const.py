# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

# Constants for IKEv2 RFC5996
# http://tools.ietf.org/html/rfc5996

import struct
from util import dh

__author__ = 'kimvais'

IKE_VERSION = (2 << 4 | 0)  # Major << 4 | Minor

# iSPI, rSPI, NextPayload, (MjVer, MnVer), ExchangeType, Flags, MessageID, Len
IKE_HEADER = struct.Struct('!2Q4B2L')

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

PAYLOAD_TYPES = dict(
    SA=33, # Security Association
    KE=34, # Key Exchange
    IDi=35, # Initiator identification
    IDr=36, # Responder identification
    CERT=37, # Certificate
    CERTREQ=38, # Certificate request
    AUTH=39, # Authentication
    Ni=40, # Nonce (initiator)
    Nr=40, # Nonce (responder)
    N=41, # Notify
    D=42, # Delete
    TSi=44, # Traffic selector - Initiator
    TSr=45, # Traffic selector - Responder
    SK=46, # Encrypted and authenticated
)
PAYLOAD_TYPES[None] = 0

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
    AUTH_AES_XCBC_96=(3, 5), # RFC 4307
    AUTH_HMAC_SHA1_96=(3, 2), # RFC 4307
    AUTH_HMAC_SHA2_256_128=(3, 12), # RFC 4868
    AUTH_HMAC_SHA2_384_192=(3, 13), # RFC 4868
    AUTH_HMAC_SHA2_512_256=(3, 14), # RFC 4868
    ENCR_AES_CBC=(1, 12), # RFC 4307
    ENCR_AES_CTR=(1, 13), # RFC 4307
    ENCR_CAMELLIA_CBC=(1, 23), # RFC 5529
    ENCR_CAMELLIA_CTR=(1, 24), # RFC 5529
    PRF_AES128_CBC=(2, 4), # RFC 4307
    PRF_HMAC_SHA1=(2, 2), # RFC 4307
    PRF_HMAC_SHA2_256=(2, 5), # RFC 4868
    PRF_HMAC_SHA2_384=(2, 6), # RFC 4868
    PRF_HMAC_SHA2_512=(2, 7), # RFC 4868
    ESN=(5, 1)   # RFC 5996
)
for group_id in dh.PRIMES.keys():
     TRANSFORMS['DH_GROUP_{0:d}'.format(group_id)] = (4, group_id)

TRANFORM_ATTRIBUTES = struct.Struct('!2H')  # (0b10000000 | 14), Key Length

AUTH_MAC_SIZE = 20
