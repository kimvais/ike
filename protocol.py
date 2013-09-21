import logging
import operator
import os

import payloads
import const
from util.dh import DiffieHellman


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class IKE(object):
    def __init__(self):
        self.iSPI = 0
        self.rSPI = 0
        self.diffie_hellman = DiffieHellman(14)
        self.Ni = os.urandom(32)

    def init(self):
        _payloads = list()
        _payloads.append(payloads.SA(next_payload="KE"))
        _payloads.append(payloads.KE(next_payload="Ni", diffie_hellman=self.diffie_hellman))
        _payloads.append(payloads.Nonce(nonce=self.Ni))
        self.iSPI = _payloads[0].spi
        data = reduce(operator.add, (x.data for x in _payloads))
        header = bytearray(const.IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            _payloads[0]._type,
            const.IKE_VERSION,
            const.IKE_SA_INIT,
            const.IKE_HDR_FLAGS['I'],
            0,
            (len(data) + const.IKE_HEADER.size)
        ))
        return header + data

    def parse(self, data):
        data = bytearray(data)
        header = data[0:const.IKE_HEADER.size]
        (iSPI, rSPI, next_payload, version, exchange_type, flags,
         message_id, length) = const.IKE_HEADER.unpack(header)
        if self.iSPI != iSPI:
            raise RuntimeError("Packet to another negotiation, initiator SPI "
                               "mismatch")
        if not self.rSPI:
            self.rSPI = rSPI
        elif not self.rSPI != rSPI:
            raise RuntimeError("Packet to another negotiation, responder SPI "
                               "mismatch")
        remainder = data[const.IKE_HEADER.size:]
        _payloads = list()
        while next_payload:
            logger.debug('Next payload: {0}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(remainder)))
            payload = payloads.BY_TYPE[next_payload](data=remainder)
            _payloads.append(payload)
            logger.critical(payload)
            next_payload = payload.next_payload
            remainder = remainder[payload.length:]
        logger.debug("outta loop")



