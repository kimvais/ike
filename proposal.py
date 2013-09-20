# -*- coding: utf-8 -*-
#
# Copyright © 2013 Kimmo Parviainen-Jalanko.
#
import os
import operator
import struct
import const

__author__ = 'kimvais'


class Proposal(object):
    PROTOCOL_IDS = dict(IKE=1, ESP=3)

    def __init__(self, num=1, protocol='IKE', spi=None, spi_len=0, last=False, transforms=None):
        if transforms == None:
            self.transforms = list()
        else:
            self.transforms = [Transform(*x) for x in transforms]
            self.transforms[-1].last = True
        self.last = last
        self.num = num
        self.protocol_id = Proposal.PROTOCOL_IDS[protocol]
        if spi is not None:
            spi_str = spi
            self.spi_len = len(spi)
        else:
            self.spi_len = spi_len
        if not self.spi_len:
            if protocol == "IKE":
                self.spi_len = 8
            elif protocol in ('ESP', 'AH'):
                self.spi_len = 4
            spi_str = os.urandom(self.spi_len)
        if self.spi_len == 8:
            self.spi, = struct.unpack('!Q', spi_str)
        elif self.spi_len == 4:
            self.spi, = struct.unpack('!L', spi_str)

    @property
    def data(self):
        self.transforms[-1].last = True
        parts = [x.data for x in self.transforms]
        self.len = const.PROPOSAL_STRUCT.size + self.spi_len + sum(len(x) for x in parts)
        last = 0 if self.last else 2
        parts.insert(0, bytearray(const.PROPOSAL_STRUCT.pack(
            last,
            0,
            self.len,
            self.num,
            self.protocol_id,
            self.spi_len,
            len(self.transforms),
        )))
        if self.spi_len == 8:
            spi = struct.pack('!Q', self.spi)
        else:
            spi = struct.pack('!L', self.spi)
        parts.insert(1, spi)
        return reduce(operator.add, parts)


class Transform(object):
    def __init__(self, name, keysize=None, last=False):
        super(Transform, self).__init__()
        self.attributes = list()
        self.last = last
        self.transform_type, self.transform_id = const.TRANSFORMS[name]
        self.keysize = keysize
        if self.transform_type == 1 and self.keysize is not None:
            self.attributes.append(const.TRANFORM_ATTRIBUTES.pack(
                (0b1000000000000000 | 14), self.keysize))
        self.len = (
            const.TRANSFORM_STRUCT.size +
            const.TRANFORM_ATTRIBUTES.size * len(self.attributes))

    @property
    def data(self):
        last = 0 if self.last else 3
        ret = bytearray(
            const.TRANSFORM_STRUCT.pack(
                last, 0, self.len,
                self.transform_type, 0, self.transform_id))
        for attr in self.attributes:
            ret += attr
        return ret
