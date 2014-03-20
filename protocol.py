# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#

from functools import reduce
from hmac import HMAC
import logging
import operator
import os
from hashlib import sha1
from struct import Struct, pack, unpack

from util.cipher import Camellia
import payloads
import const
import proposal
from util.dh import DiffieHellman
from util.prf import prf, prfplus


IKE_HEADER = Struct("!2Q4B2I")
Payload = Struct("!2BH")

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

    def ike_auth(self):

        plain = bytearray()

        # Add IDi (35)
        #
        EMAIL = "k@77.fi"
        plain += Payload.pack(39, 0, 8 + len(EMAIL))
        plain += pack("!B3x", 3)  # ID Type (RFC822 address) + reserved
        plain += EMAIL

        # Add AUTH (39)
        #
        PSK = "foo"

        IDi = str(plain)[4:]

        plain += Payload.pack(33, 0, 8 + const.AUTH_MAC_SIZE)  # prf always returns 20 bytes
        plain += pack("!B3x", 2)  # AUTH Type (psk) + reserved
        #print "%r\n%r" % (IDi, plain)

        SKEYSEED = prf(self.Ni + self.Nr, self.dh.key)

        print("SKEYSEED is: %r\n" % SKEYSEED)

        keymat = prfplus(SKEYSEED, (self.Ni + self.Nr +
                                    self.iSPI + self.rSPI ),
                         3 * 20 + 2 * 32 + 2 * 20)

        print("Got %d bytes of key material" % len(keymat))
        # get keys from material
        ( self.SK_d,
          self.SK_ai,
          self.SK_ar,
          self.SK_ei,
          self.SK_er,
          self.SK_pi,
          self.SK_pr ) = unpack("20s20s20s32s32s20s20s", keymat[:164])

        # Generate auth payload

        # find Nr
        for p in self.packets[1].Payloads:
            if p.type == 40:
                Nr = p.nonce
                print("Responder nonce %r" % Nr)
                break

        message1 = bytearray(self.packets[0].data)
        print("Original packet len: %d" % len(message1))
        x = Packet(message1)
        signed = message1 + Nr + prf(self.SK_pi, IDi)
        plain += prf(prf(PSK, "Key Pad for IKEv2"), signed)[:const.AUTH_MAC_SIZE]  # AUTH data

        # Add SA (33)
        #
        self.esp_SPIout = os.urandom(4)
        prop = proposal.Proposal(protocol='ESP', spi=self.esp_SPIout, last=True, transforms=[
            ('ENCR_CAMELLIA_CBC',), ('ESN',), ('AUTH_HMAC_SHA2_256_128',)])
        plain += Payload.pack(44, 0, len(prop) + 4) + prop

        # Generate traffic selectors
        ts = pack("!2BH2H2I", 7, 0, 16, 0, 0, 0, 0)  # Propose everything

        # Add TSi (44)
        plain += Payload.pack(45, 0, 8 + len(ts))
        plain += pack("!B3x", 1) + ts  # just a single TS

        # Add TSr (45)
        plain += Payload.pack(0, 0, 8 + len(ts))
        plain += pack("!B3x", 1) + ts  # just a single TS

        # Encrypt and hash
        iv = os.urandom(16)

        self.ikecrypto = Camellia(self.SK_ei, iv)
        self.ikehash = HMAC(self.SK_ai, digestmod=sha1)

        d = iv + self.ikecrypto.encrypt(plain)
        data = Payload.pack(35, 0, len(d) + 16) + d

        # IKE Header
        packet = IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            46,  # first payload (encrypted)
            self.version,
            35,  # exchange_type (AUTH)
            self.flags,
            1,  # message_id
            len(data) + IKE_HEADER.size + 12  # Len
        ) + data

        from dump import dump

        print(dump(packet))
        self.ikehash.update(packet)
        mac = self.ikehash.digest()[:12]
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
            payload = payloads.BY_TYPE[next_payload](data=remainder)
            self.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(self.payloads))
            next_payload = payload.next_payload
            remainder = remainder[payload.length:]
        logger.debug("outta loop")



