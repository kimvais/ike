#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2014 Kimmo Parviainen-Jalanko

import rsa

VerifyError = rsa.VerificationError


def sign(data, filename, hash_alg="SHA-256"):
    assert isinstance(data, bytes)
    with open(filename, 'rb') as keyfile:
        private_key = rsa.PrivateKey.load_pkcs1(keyfile.read())
    return rsa.sign(data, private_key, hash_alg)


def verify(data, signature, filename):
    with open(filename, 'rb') as publicfile:
        public_key = rsa.PublicKey.load_pkcs1(publicfile.read())
    try:
        return rsa.verify(data, signature, public_key)
    except rsa.VerificationError:
        raise
