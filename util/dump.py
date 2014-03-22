import binascii

def dump(src, length=8):
    return binascii.hexlify(src)

