About ike
=====

The goal of this project is to be a minimalistic IKEv2 (RFC 5996) implementation in Python.

## Status
This project is in early stages. Use at own risk.

It will make your IP stack talk ESP to the remote peer.

What it can do:

- Act as an initiator
- Authenticate itself and peer using raw RSA keys.
- Install ESP SAs and SPD entries to use the key material via `setkey` command from ipsec-tools.

Limitations (hardcoded values):

- Cipher algorithm is Camellia in CBC mode with 256 bit keys.
- HMAC / Hash / PRF algorithm is SHA2/256.
- IKE group is Diffie-Hellman modp 14.
- Authentication (both own private and peer public) key file paths are hardcoded.
- 'setkey' syntax is of whatever the ipsec-tools on Debian 7.1 accept.
- Traffic selectors are myip:any:0-65535 <-> peerip:any:0-65535

## Design principles

- Minimal amount of code.
- Support *MUST* features of draft-kivinen-ipsecme-ikev2-rfc5996bis-02 (RFC 5996
  successor)
- Use strongest algorithms possible.

## Documentation
You can read the Documentation at https://pythonhosted.org/ike

### What this project is *NOT* going to be

- ISAKMP (IKEv1) RFC 2409 compliant
- IPSec data plane / ESP protocol

## License

* MIT License

## References

* http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-rfc5996bis-02
* http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-minimal-01
