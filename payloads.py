# -*- coding: utf-8 -*-
#
# Copyright © 2013 Kimmo Parviainen-Jalanko.
#

import const

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


class _Proposal(object):
    pass


class SA(IkePayload):
    _type = 33

    def __init__(self, next_payload=None, critical=False):
        super(SA, self).__init__(next_payload, critical)
        self.proposals = list()

    @property
    def data(self):
        ret = list()
        self.proposals[-1].last = True
        ret.append(proposal.data for proposal in self.proposals)
        self.length = 4 + sum((len(x) for x in ret))
        ret.insert(0, self.header)
        return ''.join(ret)

    def add_proposal(self, proposal):
        self.proposals.append(proposal)

