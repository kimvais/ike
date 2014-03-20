# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

import logging

# TODO: Replace Twisted with asyncio - will require Python 3.4
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from protocol import IKE, Packet


logging.basicConfig(level=logging.DEBUG)


class IKEInitiator(DatagramProtocol):
    def __init__(self):
        self.ike = IKE()

    def startProtocol(self):
        host = "192.168.0.9"
        port = 500

        self.transport.connect(host, port)
        print("now we can only send to host %s port %d" % (host, port))
        self.transport.write(self.ike.init())  # no need for address

    def datagramReceived(self, data, address):
        (host, port) = address
        print("received %r from %s:%d" % (data, host, port))
        self.ike.packets.append(Packet(data=data))

    # Possibly invoked if there is no server listening on the
    # address to which we are sending.
    def connectionRefused(self):
        print("No one listening")


def main():
    # 0 means any port, we don't care in this case
    reactor.listenUDP(0, IKEInitiator())
    reactor.run()


if __name__ == '__main__':
    main()
