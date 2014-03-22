# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

import logging
import asyncio

from protocol import IKE, parse_packet


class IKEInitiator(asyncio.DatagramProtocol):
    def __init__(self):
        self.ike = IKE()

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(self.ike.init())  # no need for address

    def datagram_received(self, data, address):
        (host, port) = address
        logger.info("received %r from %s:%d" % (data, host, port))
        packet = parse_packet(data=data, ike=self.ike)
        logger.debug("Got responder SPI: {0:x}".format(packet.rSPI))
        self.ike.rSPI = packet.rSPI
        self.ike.packets.append(packet)
        ike_auth = self.ike.auth()
        self.transport.sendto(ike_auth)
        # self.ike.packets.append(Packet(data=ike_auth))
        logger.info("IKE AUTH SENT")

    # Possibly invoked if there is no server listening on the
    # address to which we are sending.
    def connectionRefused(self):
        logger.info("No one listening")


def main():
    host = "192.168.0.9"
    port = 500
    loop = asyncio.get_event_loop()
    t = asyncio.Task(loop.create_datagram_endpoint(IKEInitiator, remote_addr=(host, port)))
    loop.run_until_complete(t)
    loop.run_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('MAIN')
    logger.setLevel(logging.DEBUG)
    logger.debug("testing")
    main()
