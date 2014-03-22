import math

__author__ = 'kimvais'


def to_bytes(x):
    # Converts an integer of arbitrary length to network-endian bytes
    l = math.ceil(x.bit_length() / 8)
    return x.to_bytes(l, 'big')