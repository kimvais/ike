# -*- coding: utf-8 -*-
#
# Copyright © 2013-2014 Kimmo Parviainen-Jalanko.
#

import os
import subprocess
import tempfile

__author__ = 'kimvais'


def run_setkey(input):
    """
    Runs a script through the 'setkey' command that is a user space insterface for PFKEY.
    :param input: setkey configuration file contents.
    """
    SETKEY_BINARY = '/usr/sbin/setkey'
    fd, filename = tempfile.mkstemp('w')
    f = os.fdopen(fd, 'w')
    f.write(input)
    f.close()
    output = subprocess.check_output(['sudo', SETKEY_BINARY, '-f', filename])
    os.remove(filename)
    return output.decode('utf-8')