import logging
import operator
import os

import payloads
import const
from util.dh import DiffieHellman


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class IKE(object):
    def __init__(self, dh_group=14, nonce_len=32):
        self.iSPI = 0
        self.rSPI = 0
        self.diffie_hellman = DiffieHellman(dh_group)
        self.Ni = os.urandom(nonce_len)
        self.packets = list()

    def init(self):
        self.packets.append(Packet())
        return self.packets[-1].sa_init(self.diffie_hellman, self.Ni)


class Packet(object):
    def __init__(self, data=None, exchange_type=None):
        self.payloads = list()
        self.data = ''
        self.iSPI = self.rSPI = 0
        self.length = 0
        self.header = ''
        if data is not None:
            self.parse(data)

    def sa_init(self, dh, nonce=None):
        self.payloads.append(payloads.SA(next_payload="KE"))
        self.payloads.append(payloads.KE(next_payload="Ni",
                                         diffie_hellman=dh))
        self.payloads.append(payloads.Nonce())
        self.iSPI = self.payloads[0].spi
        self.data = reduce(operator.add, (x.data for x in self.payloads))
        self.header = bytearray(const.IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            self.payloads[0]._type,
            const.IKE_VERSION,
            const.IKE_SA_INIT,
            const.IKE_HDR_FLAGS['I'],
            0,
            (len(self.data) + const.IKE_HEADER.size)
        ))
        return self.header + self.data

    def parse(self, data):
        data = bytearray(data)
        self.header = data[0:const.IKE_HEADER.size]
        (self.iSPI, self.rSPI, next_payload, self.version, self.exchange_type, self.flags,
         self.message_id, self.length) = const.IKE_HEADER.unpack(self.header)
        remainder = data[const.IKE_HEADER.size:]
        while next_payload:
            logger.debug('Next payload: {0}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(remainder)))
            payload = payloads.BY_TYPE[next_payload](data=remainder)
            self.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(self.payloads))
            next_payload = payload.next_payload
            remainder = remainder[payload.length:]
        logger.debug("outta loop")



