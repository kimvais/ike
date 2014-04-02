#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

import logging
import asyncio
import docopt

__doc__ = """
IKE v2 (RFC 5996) initiator implementation

Usage:
    {} <remote_peer>
""".format(__file__)

from ike.protocol import IKE, parse_packet, State


class IKEInitiator(asyncio.DatagramProtocol):
    def __init__(self):
        self.ike = IKE()

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Sending INIT")
        self.transport.sendto(self.ike.init())  # no need for address

    def datagram_received(self, data, address):
        (host, port) = address
        logger.info("Received %r from %s:%d" % (data, host, port))
        # TODO: Read SPIs and Exchange type and decide what to do based on that instead of
        # doing it like this:
        packet = parse_packet(data=data, ike=self.ike)
        logger.debug("Got responder SPI: {0:x}".format(packet.rSPI))
        self.ike.rSPI = packet.rSPI
        self.ike.packets.append(packet)
        if self.ike.state == State.INIT:
            ike_auth = self.ike.auth()
            logger.info("Sending AUTH")
            self.transport.sendto(ike_auth)
            # self.ike.packets.append(Packet(data=ike_auth))
            logger.info("IKE AUTH SENT")

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
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('MAIN')
    logger.setLevel(logging.DEBUG)
    logger.info("Starting...")
    main(opts['<remote_peer>'])
