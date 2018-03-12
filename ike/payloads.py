# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#
"""
IKEv2 Payloads as specified in RFC 5996 sections 3.2 - 3.16
"""
from enum import IntEnum
from functools import reduce
import ipaddress
import logging
import operator
import os
import struct
import binascii

from . import const
from ike.util import pubkey
from ike.util.prf import prf
from .proposal import Proposal
from .util.conv import to_bytes


PRIVATE_KEY_PEM = 'tests/private_key.pem'

__author__ = 'kimvais'

logger = logging.getLogger(__name__)


class Type(IntEnum):
    """
    Payload types from `IANA <https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-2>`_
    """
    no_next_payload = 0
    SA = 33
    KE = 34
    IDi = 35
    IDr = 36
    CERT = 37
    CERTREQ = 38
    AUTH = 39
    Nonce = 40
    Ni = 40
    Nr = 40
    Notify = 41
    Delete = 42
    Vendor = 43
    TSi = 44
    TSr = 45
    SK = 46
    CP = 47
    EAP = 48
    GSPM = 49
    IDg = 50
    GSA = 51
    KD = 52
    Fragment = 132

    def __repr__(self, *args, **kwargs):
        return '<{}: {}>'.format(self.name, self.value)


class _IkePayload(object):
    """
    Generic payload header `RFC5996 Section 3.2 <https://tools.ietf.org/html/rfc5996#section-3.2>`_
    """
    _type = None

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False):
        self._type = Type[self.__class__.__name__]
        if data is not None:
            next_payload, self.flags, self.length = const.PAYLOAD_HEADER.unpack(
                data[:const.PAYLOAD_HEADER.size])
            self.next_payload = Type(next_payload)
            self.parse(data[const.PAYLOAD_HEADER.size:self.length])
        else:
            self.next_payload = next_payload
            self.length = 0
            self._data = bytearray()
            if critical:
                self.flags = 0b10000000
            else:
                self.flags = 0

    @property
    def header(self):
        return bytearray(const.PAYLOAD_HEADER.pack(self.next_payload,
                                                   self.flags,
                                                   self.length))

    def __bytes__(self):
        return bytes(self.header + self._data)

    def __unicode__(self):
        return "IKE Payload {0!r} [{1}]".format(self._type,
                                              self.length)

    def __repr__(self):
        return '<{0}>'.format(self.__unicode__(), hex(id(self)))

    def parse(self, data):
        self._data = data


class SA(_IkePayload):
    """
    `Security Association Payload <https://tools.ietf.org/html/rfc5996#section-3.3>`_
    """
    def __init__(self, data=None, proposals=None, next_payload=Type.no_next_payload,
                 critical=False):
        super(SA, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        elif proposals is None:
            self.proposals = [
                Proposal(None, 1, const.ProtocolID.IKE, transforms=[
                    ('ENCR_CAMELLIA_CBC', 256),
                    ('PRF_HMAC_SHA2_256',),
                    ('AUTH_HMAC_SHA2_256_128',),
                    ('DH_GROUP_14',)
                ]),
                Proposal(None, 2, const.ProtocolID.ESP, transforms=[
                    ('ENCR_CAMELLIA_CBC', 256),
                    ('ESN', ),
                    ('AUTH_HMAC_SHA2_256_128',)
                ])
            ]
            self.spi = self.proposals[0].spi
        else:
            self.proposals = proposals
            self.spi = self.proposals[0].spi

    def __bytes__(self):
        ret = list()
        self.proposals[-1].last = True
        ret.extend(proposal.data for proposal in self.proposals)
        self.length = 4 + sum((len(x) for x in ret))
        ret.insert(0, self.header)
        return bytes(reduce(operator.add, ret))

    def parse(self, data):
        self.proposals = list()
        last = False
        while not last:
            proposal = Proposal(data=data)
            if proposal.spi:
                logger.debug("Setting SPI to: {}".format(proposal.spi))
                self.spi = proposal.spi
            self.proposals.append(proposal)
            last = proposal.last
            data = data[proposal.len:]
        logger.debug("got {} proposals".format(len(self.proposals)))


class KE(_IkePayload):
    """
    `Key Exchange Payload <https://tools.ietf.org/html/rfc5996#section-3.4>`_
    """
    def parse(self, data):
        self.group, _ = struct.unpack('!2H', data[4:8])
        self.kex_data = data[const.PAYLOAD_HEADER.size + 4:self.length]
        logger.debug("group {}".format(self.group))
        logger.debug('KEX data: {}'.format(binascii.hexlify(self.kex_data)))

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False,
                 group=14, diffie_hellman=None):
        super(KE, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        else:
            self.kex_data = to_bytes(diffie_hellman.public_key)
            self._data = struct.pack('!2H', group, 0) + self.kex_data
            self.length = const.PAYLOAD_HEADER.size + len(self._data)


class Nonce(_IkePayload):
    """
    `Nonce Payload <https://tools.ietf.org/html/rfc5996#section-3.9>`_
    """
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False,
                 nonce=None):
        super(Nonce, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        else:
            if nonce:
                self._data = nonce
            else:
                self._data = os.urandom(32)
            self.length = const.PAYLOAD_HEADER.size + len(self._data)


class Vendor(_IkePayload):
    """
    `Nonce Payload <https://tools.ietf.org/html/rfc5996#section-3.12>`_
    """
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False,
                 vendor=None):
        super(Vendor, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        else:
            if vendor:
                self._data = vendor
            else:
                self._data = os.urandom(32)
            self.length = const.PAYLOAD_HEADER.size + len(self._data)


class Notify(_IkePayload):
    """
    `Notify Payload <https://tools.ietf.org/html/rfc5996#section-3.10>`_
    """
    def __init__(self, notify_type=None, data=None, next_payload=Type.no_next_payload, critical=False):
        # TODO; Implement generation of notifications with data
        assert notify_type or data
        super().__init__(data, next_payload, critical)
        if notify_type:
            self._data = struct.pack('!2BH', 0, 0, notify_type)
            self.length = 8

    def parse(self, data):
        self._data = data[4:self.length]
        self.protocol_id, self.spi_size, message_type = struct.unpack(
            '!2BH', data[:4])
        self.spi = data[4:4 + self.spi_size]
        self.message_type = const.MessageType(message_type)
        if self.message_type < 2 ** 14:
            self.level = logging.ERROR
        else:
            self.level = logging.INFO
        logger.log(self.level, self.__unicode__())
        self.notification_data = data[4 + self.spi_size:self.length]

    def __unicode__(self):
        if self.protocol_id:
            return '<Notify payload for {0}: {1!r} (spi {2} [{3}]) [{4}]>'.format(
                const.ProtocolID(self.protocol_id),
                self.message_type, binascii.hexlify(self.spi),
                self.spi_size, self.length)
        else:
            return '<Notify payload {0!r} [{1}]>'.format(self.message_type, self.length)


class Fragment(_IkePayload):
    """
    `Fragment Payload`
    """
    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False,
                 fragment=None):
        super(Fragment, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        else:
            if fragment:
                self._data = fragment
                self.length = const.PAYLOAD_HEADER.size + len(self._data)


class _TS(_IkePayload):
    """
    `Traffic Selector Payload <https://tools.ietf.org/html/rfc5996#section-3.13>`_
    Single IPv4 address:port
    """
    def __init__(self, addr=None, data=None, next_payload=Type.no_next_payload, critical=False):
        assert addr or data
        super().__init__(data, next_payload, critical)
        if addr:
            ip = int(ipaddress.IPv4Address(addr[0]))
            port = addr[1]
            port = 0

            # Generate traffic selector
            selector = struct.pack("!2BH2H2I", 7, 0, 16, port, port, ip, ip)
            self._data = struct.pack("!B3x", 1) + selector # just a single TS
            self.length = len(self._data) + 4

class TSi(_TS):
    """
    `Traffic Selector Payload <https://tools.ietf.org/html/rfc5996#section-3.13>`_ for initiator
    """
    pass


class TSr(_TS):
    """
    `Traffic Selector Payload <https://tools.ietf.org/html/rfc5996#section-3.13>`_ for responder
    """
    pass


class IDi(_IkePayload):
    """
    `Identification Payload <https://tools.ietf.org/html/rfc5996#section-3.5>`_ for initiator
    """
    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False):
        super().__init__(data, next_payload, critical)
        EMAIL = b'test@77.fi'
        self.length = 8 + len(EMAIL)
        self._data = struct.pack("!B3x", 3) + EMAIL  # ID Type (RFC822 address) + reserved


class IDr(_IkePayload):
    """
    `Identification Payload <https://tools.ietf.org/html/rfc5996#section-3.5>`_ for responder
    """
    pass


class AUTH(_IkePayload):
    """
    `Authentication Payload <https://tools.ietf.org/html/rfc5996#section-3.8>`_
    """
    def __init__(self, signed_octets=None, data=None, next_payload=Type.no_next_payload, critical=False):
        assert signed_octets or data
        super().__init__(data, next_payload, critical)
        if not data:
            # Generate auth payload

            # authentication_type = const.AuthenticationType.PSK
            authentication_type = const.AuthenticationType.RSA

            if authentication_type == const.AuthenticationType.PSK:
                PSK = b"foo"
                authentication_data = prf(prf(PSK, b"Key Pad for IKEv2"), signed_octets)[:const.AUTH_MAC_SIZE]
            elif authentication_type == const.AuthenticationType.RSA:
                # XXX: StrongSwan can not verify SHA-256 signature, so we have to use SHA-1
                authentication_data = pubkey.sign(signed_octets, PRIVATE_KEY_PEM, hash_alg='SHA-1')
            else:
                authentication_data = b''
                raise AssertionError("Unsupported authentication method")
            self.length = 8 + len(authentication_data)
            self._data = struct.pack(const.AUTH_HEADER, authentication_type) + authentication_data


class SK(_IkePayload):
    """
    `Encrypted Payload <https://tools.ietf.org/html/rfc5996#section-3.14>`_
    """
    def __init__(self, data=None, next_payload=Type.no_next_payload, critical=False, iv=None, ciphertext=None):
        assert data or (iv and ciphertext)
        super().__init__(data, next_payload, critical)
        if not data:
            self.iv = iv
            self.ciphertext = ciphertext
            self.length = len(iv) + len(ciphertext) + const.PAYLOAD_HEADER.size + 16 # MACLEN
            self._data = self.iv + self.ciphertext + b'\x00' * 16

    def mac(self, hmac):
        self._data = self._data[:-16] + hmac


# Register payloads in order to be used for get_by_type()
_payload_classes = _IkePayload.__subclasses__() + _TS.__subclasses__()
_payload_map = {x.__name__: x for x in _payload_classes if not x.__name__.startswith('_')}


def get_by_type(payload_type):
    """
    Returns an IkePayload (sub)class based on the RFC5996 payload_type
    :param payload_type: int() Ike Payload type
    """
    return _payload_map.get(Type(payload_type).name, _IkePayload)

