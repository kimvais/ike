About ike
=========

The goal of this project is to be a minimalistic IKEv2 (RFC 5996)
implementation in Python.

Status
------

This project is in *very* early stages. Use at own risk.

It is *almost* possible to install ESP SAs negotiated using this library
manually using 'setkey -f'.

Design principles
-----------------

-  Minimal amount of code.
-  Support *MUST* features of draft-kivinen-ipsecme-ikev2-rfc5996bis-02
   (RFC 5996 successor)
-  Use strongest algorithms possible.

Documentation
-------------

You can read the Documentation at https://ike.readthedocs.org

What this project is *NOT* going to be
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  ISAKMP (IKEv1) RFC 2409 compliant
-  IPSec data plane / ESP protocol

License
-------

-  MIT License

References
----------

-  http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-rfc5996bis-02
-  http://tools.ietf.org/html/draft-kivinen-ipsecme-ikev2-minimal-01

