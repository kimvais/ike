# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#

"""
High level interface to `IKEv2 protocol <http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-rfc5996bis-02>`_
"""
from enum import IntEnum
from functools import reduce
from hmac import HMAC
import logging
import operator
import os
from hashlib import sha256
from struct import unpack
import binascii
import struct

from . import payloads
from ike.util import pubkey
from ike.util.external import run_setkey
from .util.dump import dump
from .util.cipher import Camellia
from . import const
from . import proposal
from .util.conv import to_bytes
from .util.dh import DiffieHellman
from .util.prf import prf, prfplus


SPDADD_SYNTAX = """
spdadd {myip}[any] {peerip}[any] any -P out ipsec esp/tunnel/{myip}-{peerip}/require;
spdadd {peerip}[any] {myip}[any] any -P in ipsec esp/tunnel/{peerip}-{myip}/require;
"""
ESP_ADD_SYNTAX = 'add {ip_from} {ip_to} esp {spi} -m tunnel -E camellia-cbc 0x{key_e} -A hmac-sha256 0x{key_a}'

MACLEN = 16

logger = logging.getLogger(__name__)


class State(IntEnum):
    STARTING = 0
    INIT = 1
    AUTH = 2


class IkeError(Exception):
    pass


class IKE(object):
    """
    A single IKE negotiation / SA.

    Currently implements only Initiator side of the negotiation.
    """
    def __init__(self, address, peer, dh_group=14, nonce_len=32):
        """

        :param address: local address tuple(host, port)
        :param peer: remote address tuple(host, port)
        :param dh_group: diffie hellman group number
        :param nonce_len: length of Nonce data
        """
        self.iSPI = 0  # XXX: Should be generated here and passed downwards
        self.rSPI = 0
        self.diffie_hellman = DiffieHellman(dh_group)
        self.Ni = os.urandom(nonce_len)
        self.packets = list()
        self.state = State.STARTING
        self.address = address
        self.peer = peer

    def init_send(self):
        """
        Generates the first (IKE_INIT) packet for Initiator

        :return: bytes() containing a valid IKE_INIT packet
        """
        packet = Packet()
        self.packets.append(packet)
        packet.add_payload(payloads.SA())
        packet.add_payload(payloads.KE(diffie_hellman=self.diffie_hellman))
        packet.add_payload(payloads.Nonce(nonce=self.Ni))
        packet.iSPI = self.iSPI = packet.payloads[0].spi
        self.state = State.INIT
        return bytes(packet)

    def auth_send(self):
        """
        Generates the second (IKE_AUTH) packet for Initiator

        :return: bytes() containing a valid IKE_INIT packet
        """
        assert len(self.packets) == 2
        packet = Packet(exchange_type=const.ExchangeType.IKE_AUTH, iSPI=self.iSPI, rSPI=self.rSPI)

        # Add IDi (35)
        id_payload = payloads.IDi()
        packet.add_payload(id_payload)

        # Add AUTH (39)
        signed_octets = bytes(self.packets[0]) + self.Nr + prf(self.SK_pi, id_payload._data)
        packet.add_payload(payloads.AUTH(signed_octets))

        # Add SA (33)
        self.esp_SPIout = int.from_bytes(os.urandom(4), 'big')
        packet.add_payload(payloads.SA(proposals=[
            proposal.Proposal(protocol=const.ProtocolID.ESP, spi=self.esp_SPIout, last=True, transforms=[
                ('ENCR_CAMELLIA_CBC', 256), ('ESN',), ('AUTH_HMAC_SHA2_256_128',)
            ])
        ]))

        # Add TSi (44)
        packet.add_payload(payloads.TSi(addr=self.address))

        # Add TSr (45)
        packet.add_payload(payloads.TSr(addr=self.peer))

        # Add N(INITIAL_CONTACT)
        packet.add_payload(payloads.Notify(notify_type=const.MessageType.INITIAL_CONTACT))

        self.packets.append(packet)
        self.state = State.AUTH

        return self.encrypt_and_hmac(packet)

    def init_recv(self):
        """
        Parses the IKE_INIT response packet received from Responder.

        Assigns the correct values of rSPI and Nr
        Calculates Diffie-Hellman exchange and assigns all keys to self.

        """
        assert len(self.packets) == 2
        packet = self.packets[-1]
        for p in packet.payloads:
            if p._type == payloads.Type.Nr:
                self.Nr = p._data
                logger.debug(u"Responder nonce {}".format(binascii.hexlify(self.Nr)))
            elif p._type == payloads.Type.KE:
                int_from_bytes = int.from_bytes(p.kex_data, 'big')
                self.diffie_hellman.derivate(int_from_bytes)
            else:
                logger.debug('Ignoring: {}'.format(p))

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

    def authenticate_peer(self, auth_data, peer_id, message):
        """
        Verifies the peers authentication.
        """
        logger.debug('message: {}'.format(dump(message)))
        signed_octets = message + self.Ni + prf(self.SK_pr, peer_id._data)
        auth_type = const.AuthenticationType(struct.unpack(const.AUTH_HEADER, auth_data[:4])[0])
        assert auth_type == const.AuthenticationType.RSA
        logger.debug(dump(auth_data))
        try:
            return pubkey.verify(signed_octets, auth_data[4:], 'tests/peer.pem')
        except pubkey.VerifyError:
            raise IkeError("Remote peer authentication failed.")

    def install_ipsec_sas(self):
        logger.debug("ESP Ai: {}".format(dump(self.esp_ai)))
        logger.debug("ESP Ar: {}".format(dump(self.esp_ar)))
        logger.debug("ESP Ei: {}".format(dump(self.esp_ei)))
        logger.debug("ESP Er: {}".format(dump(self.esp_er)))
        outbound_params = dict(spi=self.esp_SPIout,
                              key_e=binascii.hexlify(self.esp_ei).decode('ascii'),
                              key_a=binascii.hexlify(self.esp_ai).decode('ascii'),
                              ip_from=self.address[0],
                              ip_to=self.peer[0])
        inbound_params = dict(spi=self.esp_SPIin,
                               key_e=binascii.hexlify(self.esp_er).decode('ascii'),
                               key_a=binascii.hexlify(self.esp_ar).decode('ascii'),
                               ip_to=self.address[0],
                               ip_from=self.peer[0])
        setkey_input = "flush;\nspdflush;\n{0};\n{1};\n{2}\ndump esp;".format(
            ESP_ADD_SYNTAX.format( **outbound_params),
            ESP_ADD_SYNTAX.format( **inbound_params),
            SPDADD_SYNTAX.format(myip=self.address[0], peerip=self.peer[0]))
        cmd_output = run_setkey(setkey_input)
        logger.info('Ipsec SAs installed:')
        for line in cmd_output.splitlines():
            logger.info('... {}'.format(line))

    def auth_recv(self):
        """
        Handle peer's IKE_AUTH response.
        """
        id_r = auth_data = None
        for p in self.packets[-1].payloads:
            if p._type == payloads.Type.IDr:
                id_r = p
                logger.debug('Got responder ID: {}'.format(dump(bytes(p))))
            if p._type == payloads.Type.AUTH:
                auth_data = p._data
            if p._type == payloads.Type.SA:
                logger.debug('ESP_SPIin: {}'.format(p.spi))
                self.esp_SPIin = p.spi
                for proposal in p.proposals:
                    logger.debug("Proposal: {}".format(proposal.__dict__))
                    logger.debug(proposal.spi)
        if id_r is None or auth_data is None:
            raise IkeError('IDr missing from IKE_AUTH response')
        message2 = bytes(self.packets[1])
        authenticated = self.authenticate_peer(auth_data, id_r, message2)
        assert authenticated
        keymat = prfplus(self.SK_d, self.Ni + self.Nr, 4 * 32)
        (self.esp_ei,
          self.esp_ai,
          self.esp_er,
          self.esp_ar,
         ) = unpack("32s" * 4, keymat)
        # TODO: Figure out the names for the params, they _ARE_ in correct places, just the names migth mismatch.
        self.install_ipsec_sas()

    def encrypt_and_hmac(self, packet):
        """
        Encrypts and signs a Packet() using self.SK_ei and self.SK_ai

        :param packet: Unecrypted Packet() with one or more payloads.
        :return: Encrypted and signed Packet() with a single payloads.SK
        """
        final = Packet(exchange_type=packet.exchange_type, iSPI=packet.iSPI, rSPI=packet.rSPI, message_id=1)
        # Set up crypto
        iv = os.urandom(16)
        ikecrypto = Camellia(self.SK_ei, iv)
        ikehash = HMAC(self.SK_ai, digestmod=sha256)
        logger.debug('IV: {}'.format(dump(iv)))

        # Encrypt
        plain = bytes(packet)[const.IKE_HEADER.size:]
        ciphertext = ikecrypto.encrypt(plain)
        sk = payloads.SK(next_payload=packet.payloads[0]._type, iv=iv, ciphertext=ciphertext)
        final.add_payload(sk)
        logger.debug(dump(bytes(final)))

        # Sign
        ikehash.update(bytes(final)[:-MACLEN])
        mac = ikehash.digest()[:MACLEN]
        sk.mac(mac)

        logger.debug(dump(bytes(final)))
        return bytes(final)

    def decrypt(self, data):
        """
        Decrypts an encrypted (SK, 46) IKE payload using self.SK_er

        :param data: Encrypted IKE payload including headers (payloads.SK())
        :return: next_payload, data_containing_payloads
        :raise IkeError: If packet is corrupted.
        """
        next_payload, is_critical, payload_len = const.PAYLOAD_HEADER.unpack(data[:const.PAYLOAD_HEADER.size])
        next_payload = payloads.Type(next_payload)
        logger.debug("next payload: {!r}".format(next_payload))
        try:
            iv_len = 16
            iv = bytes(data[const.PAYLOAD_HEADER.size:const.PAYLOAD_HEADER.size + iv_len])
            ciphertext = bytes(data[const.PAYLOAD_HEADER.size + iv_len:payload_len])  # HMAC size
        except IndexError:
            raise IkeError('Unable to decrypt: Malformed packet')
        logger.debug('IV: {}'.format(dump(iv)))
        logger.debug('CIPHERTEXT: {}'.format(dump(ciphertext)))
        # Decrypt
        cipher = Camellia(self.SK_er, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        logger.debug("Decrypted packet from responder: {}".format(dump(decrypted)))
        return next_payload, decrypted

    def verify_hmac(self, data):
        """
        Verifies the HMAC signature of an encrypted (SK, 46) payload using self.SK_ar

        :param data: bytes(payloads.SK())
        :raise IkeError: if calculated signature does not match the one in the payload
        """
        hmac = HMAC(self.SK_ar, digestmod=sha256)
        hmac_theirs = data[-MACLEN:]
        hmac.update(data[:-MACLEN])
        hmac_ours = hmac.digest()[:MACLEN]
        logger.debug('HMAC verify (ours){} (theirs){}'.format(
            binascii.hexlify(hmac_ours), binascii.hexlify(hmac_theirs)))
        if hmac_ours != hmac_theirs:
            raise IkeError('HMAC verify failed')

    def parse_packet(self, data):
        """
        Parses a received packet in to Packet() with corresponding payloads.
        Will decrypt encrypted packets when needed.

        :param data: bytes() IKE packet from wire.
        :return: Packet() instance
        :raise IkeError: on malformed packet
        """
        packet = Packet(data=data)
        packet.header = data[0:const.IKE_HEADER.size]
        (packet.iSPI, packet.rSPI, next_payload, packet.version, exchange_type, packet.flags,
         packet.message_id, packet.length) = const.IKE_HEADER.unpack(packet.header)
        packet.exchange_type = const.ExchangeType(exchange_type)
        if self.iSPI != packet.iSPI:
            raise IkeError("Initiator SPI mismatch, packet to an unknown IKE SA")
        elif not self.rSPI:
            logger.debug("Setting responder SPI: {0:x}".format(packet.rSPI))
            self.rSPI = packet.rSPI
        elif self.rSPI != packet.rSPI:
            raise IkeError("Responder SPI mismatch, packet to an unknown IKE SA")
        if packet.message_id - int(self.state) != 1:
            logger.debug("message ID {} at state {!r}".format(packet.message_id, self.state))
        logger.debug("next payload: {!r}".format(next_payload))
        if next_payload == 46:
            self.verify_hmac(data)
            next_payload, data = self.decrypt(data[const.IKE_HEADER.size:])
        else:
            data = data[const.IKE_HEADER.size:]
        while next_payload:
            logger.debug('Next payload: {0!r}'.format(next_payload))
            logger.debug('{0} bytes remaining'.format(len(data)))
            try:
                payload = payloads.get_by_type(next_payload)(data=data)
            except KeyError as e:
                logger.error("Unidentified payload {}".format(e))
                payload = payloads._IkePayload(data=data)
            packet.payloads.append(payload)
            logger.debug('Payloads: {0!r}'.format(packet.payloads))
            next_payload = payload.next_payload
            data = data[payload.length:]
        logger.debug("Packed parsed successfully")
        self.packets.append(packet)
        return packet


class Packet(object):
    """
    An IKE packet.

    To generate packets:

    #. instantiate an Packet()
    #. add payloads by Packet.add_payload(<payloads.IkePayload instance>)
    #. send bytes(Packet) to other peer.

    Received packets should be generated by IKE.parse_packet().
    """
    def __init__(self, data=None, exchange_type=None, message_id=0, iSPI=0, rSPI=0):
        self.raw_data = data
        if exchange_type is None:
            exchange_type=const.ExchangeType.IKE_SA_INIT
        self.payloads = list()
        self.iSPI = iSPI
        self.rSPI = rSPI
        self.message_id = message_id
        self.exchange_type = exchange_type

    def add_payload(self, payload):
        """
        Adds a payload to packet, updating last payload's next_payload field
        """
        if self.payloads:
            self.payloads[-1].next_payload = payload._type
        self.payloads.append(payload)

    def __bytes__(self):
        if self.raw_data is not None:
            return self.raw_data
        data = reduce(operator.add, (bytes(x) for x in self.payloads))
        length = len(data) + const.IKE_HEADER.size
        header = bytearray(const.IKE_HEADER.pack(
            self.iSPI,
            self.rSPI,
            self.payloads[0]._type,
            const.IKE_VERSION,
            self.exchange_type,
            const.IKE_HDR_FLAGS['I'],
            self.message_id,
            length
        ))
        return bytes(header + data)





