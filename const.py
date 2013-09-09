import struct

__author__ = 'kimvais'

IKE_VERSION = (2 << 4 | 0)  # Major << 4 | Minor

# iSPI, rSPI, NextPayload, (MjVer, MnVer), ExchangeType, Flags, MessageID, Len
IKE_HEADER = struct.Struct('!2Q4B2Q')

IKE_SA_INIT = 34
IKE_AUTH = 35
CREATE_CHILD_SA = 36
INFORMATIONAL = 37

HDR_FLAGS = dict(
    R=0b00100000,
    I=0b00001000
)

PAYLOAD_HEADER = struct.Struct('2BH')  # Next Payload, Flags (Critical bit), Len

PAYLOAD_TYPES = dict(
    None=0,  # No next payload
    SA=33,  # Security Association
    KE=34,  # Key Exchange
    IDi=35,  # Initiator identification
    IDr=36,  # Responder identification
    CERT=37,  # Certificate
    CERTREQ=38,  # Certificate request
    AUTH=39,  # Authentication
    Ni=40,  # Nonce (initiator)
    Nr=40,  # Nonce (responde)
    N=41,  # Notify
    D=42,  # Delete
    TSi=44,  # Traffic selector - Initiator
    TSr=45,  # Traffic selector - Responder
    SK=46,   # Encrypted and authenticated
)

