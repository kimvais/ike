# -*- coding: utf-8 -*-
#
# Copyright © 2013 Kimmo Parviainen-Jalanko.
#
import operator

import const
from proposal import Proposal

__author__ = 'kimvais'


class IkePayload(object):
    _type = None

    def __init__(self, data=None, next_payload=None, critical=False):
        if data is not None:
            pass
            # Parse
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


class SA(IkePayload):
    _type = 33

    def __init__(self, data=None, proposals=None, next_payload=None,
                 critical=False):
        super(SA, self).__init__(data, next_payload, critical)
        if proposals == None:
            self.proposals = [
                Proposal(1, 'IKE', transforms=[
                    ('ENCR_AES_CBC', 256),
                    ('PRF_HMAC_SHA2_256',),
                    ('AUTH_HMAC_SHA2_256_128',),
                    ('DH_GROUP_14',)
                ]),
                Proposal(2, 'ESP', transforms=[
                    ('ENCR_AES_CBC', 256),
                    ('AUTH_HMAC_SHA2_256_128',)
                ])
            ]
        else:
            self.proposals = proposals

    @property
    def data(self):
        ret = list()
        self.proposals[-1].last = True
        ret.extend(proposal.data for proposal in self.proposals)
        self.length = 4 + sum((len(x) for x in ret))
        ret.insert(0, self.header)
        return reduce(operator.add, ret)

