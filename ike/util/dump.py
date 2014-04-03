import binascii

def dump(src):
    """
    Returns data in hex format in groups of 4 octets delimited by spaces for debugging purposes.
    """
    return b' '.join(binascii.hexlify(bytes(x)) for x in zip(src[::4], src[1::4], src[2::4], src[3::4]))
