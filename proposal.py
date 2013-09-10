# -*- coding: utf-8 -*-
#
# Copyright © 2013 Kimmo Parviainen-Jalanko.
#
import os
from Crypto.Random.random import getrandbits
import const

__author__ = 'kimvais'


class Proposal(object):
    PROTOCOL_IDS = dict(IKE=1, ESP=3)
    def __init__(self, num=1, protocol='IKE', spi_len=0):
        self.transforms = list()
        self.last = False
        self.num = num
        self.protocol_id = Proposal.PROTOCOL_IDS[protocol]
        if spi_len:
            self.spi = os.urandom(spi_len)
        else:
            self.spi = ''

    @property
    def data(self):
        self.transforms[-1].last = True
        ret = [x.data for x in self.transforms]
        self.length = 4 + sum(len(x) for x in ret)
        last = 0 if self.last else 2
        ret.insert(0, const.PROPOSAL_STRUCT.pack(
            last,
            0,
            self.length,
            self.num,
            self.protocol_id,
            len(self.spi),
            len(self.transforms),
        ))
        ret.insert(1, self.spi)
        return ''.join(ret)

class Transform(object):
    def __init__(self):
        super(Transform, self).__init__()
