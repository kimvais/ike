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


class IKEInitiator(asyncio.DatagramProtocol):

    def connection_made(self, transport):
        from ike.protocol import IKE
        self.transport = transport
        sock = self.transport.get_extra_info("socket")
        address = sock.getsockname()
        peer = sock.getpeername()
        logger.debug("Socket created from {} to {}".format(address, peer))
        self.ike = IKE(address, peer)
        logger.info("Sending INIT")
        self.transport.sendto(self.ike.init())  # no need for address

    def datagram_received(self, data, address):
        from ike.protocol import State
        (host, port) = address
        logger.info("Received %r from %s:%d" % (data, host, port))
        self.ike.parse_packet(data=data)
        # TODO: Read SPIs and Exchange type and decide what to do based on that instead of
        # doing it like this:
        if self.ike.state == State.INIT:
            self.ike.init_response_recv()
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
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(path)s:%(lineno)s: %(message)s')
    logger = logging.getLogger('MAIN')
    logger.setLevel(logging.DEBUG)
    logger.info("Starting...")
    main(opts['<remote_peer>'])
