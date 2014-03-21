# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#
from functools import reduce
import logging
import operator
import os
import struct
import binascii

import const
from proposal import Proposal


__author__ = 'kimvais'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class IkePayload(object):
    _type = None

    def __init__(self, data=None, next_payload=None, critical=False):
        if data is not None:
            self.next_payload, self.flags, self.length = const.PAYLOAD_HEADER.unpack(
                data[:const.PAYLOAD_HEADER.size])
            self.parse(data[const.PAYLOAD_HEADER.size:])
        else:
            self.next_payload = const.PAYLOAD_TYPES[next_payload]
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

    @property
    def data(self):
        return self.header + self._data

    def __unicode__(self):
        return "IKE Payload {0} [{1}]".format(self.__class__.__name__,
                                              self.length)

    def __repr__(self):
        return '<{0} at {1}>'.format(self.__unicode__(), hex(id(self)))

    def parse(self, data):
        self._data = data

class SA(IkePayload):
    _type = 33

    def __init__(self, data=None, proposals=None, next_payload=None,
                 critical=False):
        super(SA, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        elif proposals is None:
            self.proposals = [
                Proposal(None, 1, 'IKE', transforms=[
                    ('ENCR_CAMELLIA_CBC', 256),
                    ('PRF_HMAC_SHA2_256',),
                    ('AUTH_HMAC_SHA2_256_128',),
                    ('DH_GROUP_14',)
                ]),
                Proposal(None, 2, 'ESP', transforms=[
                    ('ENCR_CAMELLIA_CBC', 256),
                    ('ESN', ),
                    ('AUTH_HMAC_SHA2_256_128',)
                ])
            ]
        else:
            self.proposals = proposals
        self.spi = self.proposals[0].spi

    @property
    def data(self):
        ret = list()
        self.proposals[-1].last = True
        ret.extend(proposal.data for proposal in self.proposals)
        self.length = 4 + sum((len(x) for x in ret))
        ret.insert(0, self.header)
        return reduce(operator.add, ret)

    def parse(self, data):
        self.proposals = list()
        last = False
        while not last:
            proposal = Proposal(data=data)
            self.proposals.append(proposal)
            last = proposal.last
            data = data[proposal.len:]


class KE(IkePayload):
    _type = 34

    def parse(self, data):
        self.group, _ = struct.unpack('!2H', data[4:8])
        self.kex_data = data[const.PAYLOAD_HEADER.size+4:self.length]
        logger.debug("group {}".format(self.group))
        logger.debug('KEX data: {}'.format(binascii.hexlify(self.kex_data)))

    def __init__(self, data=None, next_payload=None, critical=False,
                 group=14, diffie_hellman=None):
        super(KE, self).__init__(data, next_payload, critical)
        if data is not None:
            self.parse(data)
        else:
            self.kex_data = '{0:x}'.format(diffie_hellman.public_key).decode(
                'hex')
            self._data = struct.pack('!2H', group, 0) + self.kex_data
            self.length = const.PAYLOAD_HEADER.size + len(self._data)


class Nonce(IkePayload):
    _type = 40

    def parse(self, data):
        self._data = data[const.PAYLOAD_HEADER.size:self.length]

    def __init__(self, data=None, next_payload=None, critical=False,
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


class Notify(IkePayload):
    def parse(self, data):
        self._data = data[4:self.length]
        self.protocol_id, self.spi_size, self.message_type = struct.unpack(
            '!2BH', data[:4])
        self.spi = data[4:4 + self.spi_size]
        logger.info(
            'Notify for {0}: {1} (spi {2} [{3}])'.format(self.protocol_id,
                                                         self.message_type,
                                                         binascii.hexlify(self.spi),
                                                         self.spi_size))
        self.notification_data = data[4 + self.spi_size:self.length]


class IDi(IkePayload):
    pass

class IDr(IkePayload):
    pass

BY_TYPE = {
    33: SA,
    34: KE,
    35: IDi,
    36: IDr,
    40: Nonce,
    41: Notify,
}