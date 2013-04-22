Sharing Secrets
===============
Every now and then we have a need to share a "secret" with some
co-workers.  Coordinating this can be problematic, since you would either
need to be in the same physical space at the same time, or you would need
to be able to talk over the phone (and know that who you're talking to is
in fact the person you think you're talking to) etc. etc.

Wouldn't it be nice if you could just attach the file in question to an
email, insert it into a ticketing system, or drop it on a shared host?

Using SSH Keys
==============
Many organizations already use SSH keys for access to their hosts. That is,
you have a central place (local file systems on shared hosts as well as,
perhaps, LDAP) where you have public keys that you already trust to belong
to the given person.  Most engineers are familiar with ssh(1) and the use
of ssh keys for authentication, but what not everybody might be aware of
is that by their very nature these keys can also be used for encryption of
non-SSH related data.

The commands to do this are not very complex, but the combination is
generally longer than any of us would like to have to remember.  jass(1)
wraps these commands with a lot of convenience glue and presents a
simplified user interface to allow for the encryption of data with the
public ssh keys of the specified recipients, as well as the decryption
using the given private ssh key.


Supported Platforms
===================
jass(1) is written in shell, so it should run pretty much anywhere. It
currently requires base64(1), ssh-keygen(1), openssl(1), and uuencode(1).

We rely on ssh-keygen(1)'s ability to convert the public ssh key from
OpenSSH's (effectively) proprietary default format to PKCS8; this feature
was added in OpenSSH version 5.6.

jass(1) was tested on the following systems:

- CentOS release 5.5
- FreeBSD 9.1-RELEASE
- Mac OS X 10.8.3
- NetBSD 6.0.1
- Ubuntu 13.04 Raring Ringtail


How to install jass(1)
======================
jass(1) allows you to query LDAP for ssh keys.  If you are using this
feature, edit the file src/jass and set the two LDAP* variables near
the top of the script.


Just copy the manual page from doc/jass.1 to somewhere in your MANPATH and
the script src/jass to somewhere in your PATH.

The simplistic provided Makefile will copy those files under /usr/local or
wherever PREFIX points to.


How to use jass(1)
==================

Encrypting data
---------------
To encrypt the file service.yml for the local user jschauma and send it
via email:

    $ jass -u jschauma <service.yml | \
            mail -s "Please do the needful!" jschauma

Please see the manual page for details and other examples.

Decrypting data
---------------

To decrypt data, you need to have access to the private ssh key in
question. This means that this should not happen on a shared box but
instead is likely to occur on your desktop, laptop or other private
system:

    jass -d -k ~/.ssh/privkey <secret

FAQ
===

Why does jass(1) say "Unable to convert ssh key to PKCS8 format."?
------------------------------------------------------------------
The command that failed here was:

    ssh-keygen -P '' -f "${pubkey}" -e -m PKCS8

Most likely your version of ssh-keygen(1) does not support conversion to
PKCS8.  This capability was added in OpenSSH 5.6 -- if your version of
ssh(1) is less than that, jass(1) will not work.  Check the output of 'ssh
-V' and/or review the manual page for ssh-keygen(1) to ensure it supports
the '-m PKCS8' flag.


Why don't we just use PGP?
--------------------------
Why indeed. PGP has many advantages and more widespread use would make
things a lot easier, but very few people appear to use it. If you're
interested in getting an introduction to PGP, I'll gladly come and give
you and your team a presentation.

Why does this ask me for my passphrase when decrypting? Can't it get it from my ssh agent?
------------------------------------------------------------------------------------------
Unfortunately the passphrase cannot be retrieved from any running ssh
agent, since we are not actually using ssh(1) at all. We are using
openssl(1), which requires the passphrase to use the private key file to
decrypt the data.

Who wrote this tool?
--------------------
jass(1) was originally written by Jan Schaumann (jschauma@netmeister.org) in
April 2013.
