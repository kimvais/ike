# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko.
#
from hmac import HMAC
import hashlib
from struct import pack


def prf(key, data, hash_algorithm='sha256'):
    hasher = getattr(hashlib, hash_algorithm)
    m = HMAC(key, digestmod=hasher)
    m.update(data)
    return m.digest()


def prfplus(key, data, n):
    ret = str()
    prev = ''
    round = 1
    while len(ret) < n:
        prev = prf(key, prev + data + pack("!B", round))
        ret += prev
        round += 1
    return ret[:n]