#########################
SSH2 (en/de)crypt utility
#########################

:Version:   1.2
:Date:      2015-09-20

**Use existing ssh public keys** [#if]_ **to encrypt files!**

.. [#if] If these keys are RSA ones :)

Objectives
==========

This utility is no more than a toy. Rather powerful toy nevertheless. It was written as a proof of concept to show ability to use almost any appropriate public keys to encrypt data.

Sometimes there appear situations, when you have no other alternatives besides coreutils and ssh installed on the host. Well… If you can install in addition openssl, why don't install GnuPG? I don't know, but this script allows encrypt and sign files using only existing ssh keys with openssl as backend.

Usage
=====

::

    ssh_crypt [--help|-h] {--enc|-e}|{--dec|-d} --pub|-p pulic_key \
              --priv|-k private_key [--sign|-s] [--armor|-a] \
              [--verbose|-v] in_filename [out_filename]

Options
-------

--help      (or -h) Show the help and exit
--enc       (or -e) Encrypt input file using ssh public key
--dec       (or -d) Decrypt input file using ssh private key
--pub=public_key  (or ``-p public_key``)
            Public key to use to encrypt data or
            to verify digital signature
--priv=private_key  (or ``-k private_key``)
            Private key to use to decrypt data or
            to digitally sign file
--sign      (or -s) Attach digital signature (private key needed)
--armor     (or -a) Save encrypted data in ASCII form
            (by default output file is binary)
--verbose   (or -v) Be verbose. To increase verbosity level
            add more ``-v`` options to command line.

Files to use
------------

in_filename
     File to encrypt (mandatory)
out_file
        File to save encrypted data. Can be omitted.

Notes
=====

* This script uses ``openssl`` as a backend. So only RSA public
  keys may be used to encrypt file. Though for signing other
  types of keys go well, such as DSA or ECDSA. But ED25519
  SSH2 keys are not compatible with ``openssl`` suite.
* Parameters ``--enc`` and ``--dec`` are mutual exclusive. If they
  appear together in the command line, only the first of them
  will be taken.
* If the name of ``out_file`` is omitted, in encryption mode
  it will be taken from ``in_filename`` with suffix *.bin* or
  *.asc* (depending of ``--armor`` option). In decryption mode
  filename will be restored from saved data or, if the file
  with the same name exists, suffix *.decrypted* will be added.
