#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko
#
import locale
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.openssl import backend
import sys


class Camellia(object):
    def __init__(self, key, iv=None):
        if iv is None:
            self.iv = os.urandom(16)
        else:
            assert len(iv) == 16
            self.iv = iv
        self.cipher = Cipher(algorithms.Camellia(key), modes.CBC(self.iv), backend=backend)
        self.enc = self.cipher.encryptor()
        self.dec = self.cipher.decryptor()

    def encrypt(self, data):
        pad = 16 - len(data) % 16
        if pad:
            data += struct.pack('B', pad) * pad
        return self.enc.update(data) + self.enc.finalize()

    def decrypt(self, data):
        plain = self.dec.update(data) + self.dec.finalize()
        padlen = plain[-1]
        return plain[:-padlen]


if __name__ == '__main__':
    c = Camellia(16 * b'k')
    ciphertext = c.encrypt(' '.join(sys.argv[1:]).encode(locale.getpreferredencoding()))
    print(ciphertext)
    print(c.decrypt(ciphertext))
