#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

import logging
import asyncio
import os
import docopt

__doc__ = """
IKE v2 (RFC 5996) initiator implementation

Usage:
    {} <remote_peer>

To clean up afterwards, ::

    setkey -FP && setkey -F

""".format(os.path.split(__file__)[-1])


class IKEInitiator(asyncio.DatagramProtocol):
    """
    Implements an IKE initiator that attempt to negotiate a single child SA
    to remote peer.
    """
    def connection_made(self, transport):
        from ike.protocol import IKE
        self.transport = transport
        sock = self.transport.get_extra_info("socket")
        address = sock.getsockname()
        peer = sock.getpeername()
        logger.debug("Socket created from {} to {}".format(address, peer))
        self.ike = IKE(address, peer)
        logger.info("Sending INIT")
        self.transport.sendto(self.ike.init_send())  # no need for address

    def datagram_received(self, data, address):
        from ike.protocol import State
        from ike.const import ExchangeType
        (host, port) = address
        logger.info("Received %r from %s:%d" % (data, host, port))
        packet = self.ike.parse_packet(data=data)
        logger.info('{} message {}'.format(packet.exchange_type.name, packet.message_id))
        if self.ike.state == State.INIT and packet.exchange_type == ExchangeType.IKE_SA_INIT:
            self.ike.init_recv()
            ike_auth = self.ike.auth_send()
            logger.info("Sending AUTH")
            self.transport.sendto(ike_auth)
            logger.info("IKE AUTH SENT")
        elif self.ike.state == State.AUTH and packet.exchange_type == ExchangeType.IKE_AUTH:
            self.ike.auth_recv()

    # Possibly invoked if there is no server listening on the
    # address to which we are sending.
    def connectionRefused(self):
        logger.info("No one listening")


def main(peer):
    port = 500
    loop = asyncio.get_event_loop()
    t = asyncio.Task(loop.create_datagram_endpoint(IKEInitiator, remote_addr=(peer, port)))
    # TODO: Retransmissions should be handled here?
    loop.run_until_complete(t)
    loop.run_forever()


if __name__ == '__main__':
    opts = docopt.docopt(__doc__)
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s.%(funcName)s:[%(lineno)s]: %(message)s')
    logger = logging.getLogger('MAIN')
    logger.info("Starting...")
    main(opts['<remote_peer>'])
