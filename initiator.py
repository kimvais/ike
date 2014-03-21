# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

import logging

# TODO: Replace Twisted with asyncio - will require Python 3.4
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from protocol import IKE, Packet


logger = logging.getLogger(__name__)

class IKEInitiator(DatagramProtocol):
    def __init__(self):
        self.ike = IKE()

    def startProtocol(self):
        host = "192.168.0.9"
        port = 500

        self.transport.connect(host, port)
        logger.info("now we can only send to host %s port %d" % (host, port))
        self.transport.write(self.ike.init())  # no need for address

    def datagramReceived(self, data, address):
        (host, port) = address
        logger.info("received %r from %s:%d" % (data, host, port))
        packet = Packet(data=data)
        self.ike.rSPI = packet.rSPI
        self.ike.packets.append(packet)
        ike_auth = self.ike.auth()
        self.transport.write(ike_auth)
        # self.ike.packets.append(Packet(data=ike_auth))
        logger.info("IKE AUTH SENT")

    # Possibly invoked if there is no server listening on the
    # address to which we are sending.
    def connectionRefused(self):
        logger.info("No one listening")


def main():
    # 0 means any port, we don't care in this case
    reactor.listenUDP(0, IKEInitiator())
    reactor.run()


if __name__ == '__main__':
    logging.basicConfig()
    main()
