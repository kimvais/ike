#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko
#
import locale
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.openssl import backend


def pad(data, blocksize=16):
    """
    Pads data to blocksize according to RFC 4303. Pad length field is included in output.
    """
    padlen = blocksize - len(data) % blocksize
    return bytes(data + bytearray(range(1, padlen)) + bytearray((padlen - 1,)))


class _Cipher(object):
    algorithm = None

    def __init__(self, key, iv=None):
        if iv is None:
            self.iv = os.urandom(16)
        else:
            assert len(iv) == 16
            self.iv = iv
        self.cipher = Cipher(self.algorithm(key), modes.CBC(self.iv), backend=backend)
        self.enc = self.cipher.encryptor()
        self.dec = self.cipher.decryptor()

    def encrypt(self, data):
        return self.enc.update(pad(data)) + self.enc.finalize()

    def decrypt(self, data):
        plain = self.dec.update(data) + self.dec.finalize()
        return plain
        padlen = plain[-1]
        return plain[:-padlen]


class Camellia(_Cipher):
    algorithm = algorithms.Camellia


class AES(_Cipher):
    algorithm = algorithms.AES


if __name__ == '__main__':
    c = Camellia(16 * b'k')
    ciphertext = c.encrypt(' '.join(sys.argv[1:]).encode(locale.getpreferredencoding()))
    print(ciphertext)
    print(c.decrypt(ciphertext))
