# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#

from functools import reduce
from hmac import HMAC
import logging
import operator
import os
from hashlib import sha1, sha256
from struct import Struct, pack, unpack
import binascii

from util.cipher import Camellia
import payloads
import const
import proposal
from util.dh import DiffieHellman
from util.prf import prf, prfplus


IKE_HEADER = Struct("!2Q4B2I")
PAYLOAD = Struct("!2BH")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def to_bytes(x):
    h = '{0:x}'.format(x)
    return ('0' * (len(h) % 2) + h).decode('hex')


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

    def auth(self):
        self.iSPI = self.packets[0].iSPI
        self.rSPI = self.packets[-1].rSPI
        self.packets.append(Packet())
        return self.packets[-1].ike_auth(self)


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

    def ike_auth(self, ike):

        plain = bytearray()
        MACLEN = 16
        # Add IDi (35)
        #
        EMAIL = "k@77.fi"
        plain += PAYLOAD.pack(39, 0, 8 + len(EMAIL))
        plain += pack("!B3x", 3)  # ID Type (RFC822 address) + reserved
        plain += EMAIL

        # Add AUTH (39)
        #
        PSK = "foo"

        IDi = str(plain)[4:]

        plain += PAYLOAD.pack(33, 0, 8 + const.AUTH_MAC_SIZE)  # prf always returns 20 bytes
        plain += pack("!B3x", 2)  # AUTH Type (psk) + reserved
        #logger.debug "%r\n%r" % (IDi, plain)

        # find Nr
        for p in ike.packets[1].payloads:
            if p._type == 40:
                ike.Nr = p._data
                logger.debug("Responder nonce %r" % ike.Nr)
            elif p._type == 34:
                # int_from_bytes = int.from_bytes(p.kex_data, 'big')
                int_from_bytes = int(str(p.kex_data).encode('hex'), 16)
                ike.diffie_hellman.derivate(int_from_bytes)

        SKEYSEED = prf(ike.Ni + ike.Nr, ike.diffie_hellman.shared_secret)

        logger.debug("SKEYSEED is: %r\n" % SKEYSEED)

        keymat = prfplus(SKEYSEED, (ike.Ni + ike.Nr +
                                    to_bytes(ike.iSPI) + to_bytes(ike.rSPI)),
                         32 * 7)
                         #3 * 32 + 2 * 32 + 2 * 32)

        logger.debug("Got %d bytes of key material" % len(keymat))
        # get keys from material
        ( ike.SK_d,
          ike.SK_ai,
          ike.SK_ar,
          ike.SK_ei,
          ike.SK_er,
          ike.SK_pi,
          ike.SK_pr ) = unpack("32s32s32s32s32s32s32s", keymat[:32 * 7])

        # Generate auth payload

        message1 = bytearray(ike.packets[0].data)
        logger.debug("Original packet len: %d" % len(message1))
        signed = message1 + ike.Nr + prf(ike.SK_pi, IDi)
        plain += prf(prf(PSK, "Key Pad for IKEv2"), signed)[:const.AUTH_MAC_SIZE]  # AUTH data

        # Add SA (33)
        #
        self.esp_SPIout = os.urandom(4)
        prop = proposal.Proposal(protocol='ESP', spi=self.esp_SPIout, last=True, transforms=[
            ('ENCR_CAMELLIA_CBC',), ('ESN',), ('AUTH_HMAC_SHA2_256_128',)])
        plain += PAYLOAD.pack(44, 0, len(prop.data) + 4) + prop.data

        # Generate traffic selectors
        ts = pack("!2BH2H2I", 7, 0, 16, 0, 0, 0, 0)  # Propose everything

        # Add TSi (44)
        plain += PAYLOAD.pack(45, 0, 8 + len(ts))
        plain += pack("!B3x", 1) + ts  # just a single TS

        # Add TSr (45)
        plain += PAYLOAD.pack(0, 0, 8 + len(ts))
        plain += pack("!B3x", 1) + ts  # just a single TS

        # Encrypt and hash
        iv = os.urandom(16)

        self.ikecrypto = Camellia(ike.SK_ei, iv)
        self.ikehash = HMAC(ike.SK_ai, digestmod=sha256)

        logger.debug('IV: {}'.format(binascii.hexlify(iv)))
        logger.debug('IKE packet in plain: {}'.format(binascii.hexlify(plain)))
        d = iv + self.ikecrypto.encrypt(plain)
        data = PAYLOAD.pack(35, 0, len(d) + PAYLOAD.size) + d

        # IKE Header
        packet = IKE_HEADER.pack(
            ike.iSPI,
            ike.rSPI,
            46,  # first payload (encrypted)
            const.IKE_VERSION,
            35,  # exchange_type (AUTH)
            const.IKE_HDR_FLAGS['I'],
            1,  # message_id
            len(data) + IKE_HEADER.size
        ) + data

        from dump import dump

        logger.debug(dump(packet))
        self.ikehash.update(packet)
        mac = self.ikehash.digest()[:MACLEN]
        logger.debug("HMAC: {}".format(mac.encode('hex')))
        return packet + mac

    def parse(self, data):
        data = bytearray(data)
        self.header = data[0:const.IKE_HEADER.size]
        (self.iSPI, self.rSPI, next_payload, self.version, self.exchange_type, self.flags,
         self.message_id, self.length) = const.IKE_HEADER.unpack(self.header)
        remainder = data[const.IKE_HEADER.size:]
        while next_payload:
            logger.debug('Next payload: {0}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(remainder)))
            try:
                payload = payloads.BY_TYPE[next_payload](data=remainder)
            except KeyError as e:
                logger.error("Unidentified payload {}".format(e))
                payload = payloads.IkePayload(data=remainder)
            self.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(self.payloads))
            next_payload = payload.next_payload
            remainder = remainder[payload.length:]
        logger.debug("Packed parsed successfully")



