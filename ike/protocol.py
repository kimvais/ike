# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#
from enum import IntEnum
from functools import reduce
from hmac import HMAC
import ipaddress
import logging
import operator
import os
from hashlib import sha256
from struct import Struct, pack, unpack
import binascii

from . import payloads
from .util import pubkey
from .util.dump import dump
from .util.cipher import Camellia
from . import const
from . import proposal
from .util.conv import to_bytes
from .util.dh import DiffieHellman
from .util.prf import prf, prfplus


IKE_HEADER = Struct("!2Q4B2I")
PAYLOAD = Struct("!2BH")
MACLEN = 16

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class State(IntEnum):
    STARTING = 0
    INIT = 1
    AUTH = 2


class IKE(object):
    def __init__(self, address, peer, dh_group=14, nonce_len=32):
        self.iSPI = 0  # XXX: Should be generated here and passed downwards
        self.rSPI = 0
        self.diffie_hellman = DiffieHellman(dh_group)
        self.Ni = os.urandom(nonce_len)
        self.packets = list()
        self.state = State.STARTING
        self.address = address
        self.peer = peer

    def init(self):
        packet = Packet()
        self.packets.append(packet)
        packet.payloads.append(payloads.SA(next_payload="KE"))
        packet.payloads.append(payloads.KE(next_payload="Ni",
                                           diffie_hellman=self.diffie_hellman))
        packet.payloads.append(payloads.Nonce(nonce=self.Ni))
        packet.iSPI = self.iSPI = packet.payloads[0].spi
        self.state = State.INIT
        return bytes(packet)

    def auth(self):
        # self.iSPI = self.packets[0].iSPI
        # self.rSPI = self.packets[-1].rSPI
        self.packets.append(Packet())
        self.state = State.AUTH
        return self.ike_auth(self)

    def init_response_recv(self):
        # find Nr
        for p in self.packets[-1].payloads:
            if p._type == 40:
                self.Nr = p._data
                logger.debug(u"Responder nonce {}".format(binascii.hexlify(self.Nr)))
            elif p._type == 34:
                int_from_bytes = int.from_bytes(p.kex_data, 'big')
                #int_from_bytes = int(str(p.kex_data).encode('hex'), 16)
                self.diffie_hellman.derivate(int_from_bytes)

        logger.debug('Nonce I: {}\nNonce R: {}'.format(binascii.hexlify(self.Ni), binascii.hexlify(self.Nr)))
        logger.debug('DH shared secret: {}'.format(binascii.hexlify(self.diffie_hellman.shared_secret)))

        SKEYSEED = prf(self.Ni + self.Nr, self.diffie_hellman.shared_secret)

        logger.debug(u"SKEYSEED is: {0!r:s}\n".format(binascii.hexlify(SKEYSEED)))

        keymat = prfplus(SKEYSEED, (self.Ni + self.Nr +
                                    to_bytes(self.iSPI) + to_bytes(self.rSPI)),
                         32 * 7)
        #3 * 32 + 2 * 32 + 2 * 32)

        logger.debug("Got %d bytes of key material" % len(keymat))
        # get keys from material
        ( self.SK_d,
          self.SK_ai,
          self.SK_ar,
          self.SK_ei,
          self.SK_er,
          self.SK_pi,
          self.SK_pr ) = unpack("32s" * 7, keymat)  # XXX: Should support other than 256-bit algorithms, really.

        logger.debug("SK_ai: {}".format(dump(self.SK_ai)))
        logger.debug("SK_ei: {}".format(dump(self.SK_ei)))

    def ike_auth(self, packet):

        plain = bytearray()
        # Add IDi (35)
        #

        plain += bytes(payloads.IDi(next_payload='AUTH'))

        # Add AUTH (39)
        #
        PSK = b"foo"

        # Generate auth payload

        IDi = bytes(plain)[PAYLOAD.size:]

        # authentication_type = const.AuthenticationType.PSK
        authentication_type = const.AuthenticationType.RSA
        #logger.debug "%r\n%r" % (IDi, plain)

        signed = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, IDi)
        if authentication_type == const.AuthenticationType.PSK:
            authentication_data = prf(prf(PSK, b"Key Pad for IKEv2"), signed)[:const.AUTH_MAC_SIZE]
        elif authentication_type == const.AuthenticationType.RSA:
            # XXX: StrongSwan can not verify SHA-256 signature, so we have to use SHA-1
            authentication_data = pubkey.sign(signed, 'tests/private_key.pem', hash_alg='SHA-1')
        plain += PAYLOAD.pack(33, 0, 8 + len(authentication_data))  # prf always returns 20 bytes
        plain += pack("!B3x", authentication_type)  # AUTH Type (psk) + reserved
        plain += authentication_data  # AUTH data

        # Add SA (33)
        #
        self.esp_SPIout = os.urandom(4)
        prop = proposal.Proposal(protocol=const.ProtocolID.ESP, spi=self.esp_SPIout, last=True, transforms=[
            ('ENCR_CAMELLIA_CBC', 256), ('ESN',), ('AUTH_HMAC_SHA2_256_128',)])
        # ('ENCR_CAMELLIA_CBC', 256), ('ESN',), ('AUTH_HMAC_SHA2_256_128',)])
        plain += PAYLOAD.pack(44, 0, len(prop.data) + 4) + prop.data

        localip = int(ipaddress.IPv4Address(self.address[0]))
        localport = self.address[1]
        peerip = int(ipaddress.IPv4Address(self.peer[0]))
        peerport = self.peer[1]

        # Generate traffic selectors
        tsi = pack("!2BH2H2I", 7, 0, 16, localport, localport, localip, localip)
        tsr = pack("!2BH2H2I", 7, 0, 16, peerport, peerport, peerip, peerip)

        # Add TSi (44)
        plain += PAYLOAD.pack(45, 0, 8 + len(tsi))  # 12 = Payload header, + B3x + TS header
        plain += pack("!B3x", 1) + tsi  # just a single TS

        # Add TSr (45)
        plain += PAYLOAD.pack(0, 0, 8 + len(tsr))
        plain += pack("!B3x", 1) + tsr  # just a single TS

        # Encrypt and hash
        iv = os.urandom(16)

        ikecrypto = Camellia(self.SK_ei, iv)

        logger.debug('IV: {}'.format(binascii.hexlify(iv)))
        logger.debug('IKE packet in plain: {}'.format(binascii.hexlify(plain)))
        # Encrypt
        ciphertext = ikecrypto.encrypt(plain)
        payload_len = PAYLOAD.size + len(iv) + len(ciphertext) + MACLEN
        enc_payload = PAYLOAD.pack(35, 0, payload_len) + iv + ciphertext

        # IKE Header
        data = IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            46,  # first payload (encrypted)
            const.IKE_VERSION,
            35,  # exchange_type (AUTH)
            const.IKE_HDR_FLAGS['I'],
            1,  # message_id
            len(enc_payload) + IKE_HEADER.size + MACLEN
        ) + enc_payload

        logger.debug("Final data: {}".format(dump(data)))
        # Sign
        ikehash = HMAC(self.SK_ai, digestmod=sha256)
        ikehash.update(data)
        mac = ikehash.digest()[:MACLEN]
        logger.debug("HMAC: {}".format(binascii.hexlify(mac)))
        return data + mac


class Packet(object):
    def __init__(self, data=None, exchange_type=None, message_id=0):
        self.payloads = list()
        if data:
            self.data = data
        else:
            self.data = b''
        self.iSPI = self.rSPI = 0
        self.length = 0
        self.header = b''
        self.message_id = message_id

    def __bytes__(self):
        self.data = reduce(operator.add, (bytes(x) for x in self.payloads))
        self.header = bytearray(const.IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            self.payloads[0]._type,
            const.IKE_VERSION,
            const.IKE_SA_INIT,
            const.IKE_HDR_FLAGS['I'],
            self.message_id,
            (len(self.data) + const.IKE_HEADER.size)
        ))
        return bytes(self.header + self.data)


class IkeError(Exception):
    pass


def parse_packet(data, ike=None):
    raw_data = data
    packet = Packet()
    data = bytearray(raw_data)
    packet.header = data[0:const.IKE_HEADER.size]
    (packet.iSPI, packet.rSPI, next_payload, packet.version, packet.exchange_type, packet.flags,
     packet.message_id, packet.length) = const.IKE_HEADER.unpack(packet.header)
    if packet.message_id - int(ike.state) != 1:
        logger.debug("message ID {} at state {}".format(packet.message_id, ike.state))
    remainder = data[const.IKE_HEADER.size:]
    logger.debug("next payload: {}".format(next_payload))
    if next_payload == 46:
        next_payload, is_critical, payload_len = PAYLOAD.unpack(remainder[:PAYLOAD.size])
        logger.debug("next payload: {}".format(next_payload))
        try:
            iv_len = 16
            iv = bytes(remainder[PAYLOAD.size:PAYLOAD.size + iv_len])
            ciphertext = bytes(remainder[PAYLOAD.size + iv_len:payload_len])  # HMAC size
            hmac_theirs = remainder[-MACLEN:]
        except IndexError:
            logger.critical('Malformed packet')

        logger.debug('IV: {}'.format(dump(iv)))
        logger.debug('CIPHERTEXT: {}'.format(dump(ciphertext)))
        hmac = HMAC(ike.SK_ar, digestmod=sha256)
        hmac.update(raw_data[:-MACLEN])
        hmac_ours = hmac.digest()[:MACLEN]
        logger.debug('HMAC verify (ours){} (theirs){}'.format(
            binascii.hexlify(hmac_ours), binascii.hexlify(hmac_theirs)))
        if hmac_ours != hmac_theirs:
            raise IkeError('HMAC verify failed')
        # Decrypt
        cipher = Camellia(ike.SK_er, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        logger.debug("Decrypted packet from responder: {}".format(dump(decrypted)))
        remainder = decrypted
    while next_payload:
        logger.debug('Next payload: {0}'.format(next_payload))
        logger.debug('{0} bytes remaining'.format(len(remainder)))
        try:
            payload = payloads.BY_TYPE[next_payload](data=remainder)
        except KeyError as e:
            logger.error("Unidentified payload {}".format(e))
            payload = payloads.IkePayload(data=remainder)
        packet.payloads.append(payload)
        logger.debug('Payloads: {0!r}'.format(packet.payloads))
        next_payload = payload.next_payload
        remainder = remainder[payload.length:]
    logger.debug("Packed parsed successfully")
    return packet


