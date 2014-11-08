Sharing Secrets
===============
Every now and then we have a need to share a "secret" with some
cow-orkers.  Coordinating this can be problematic, since you would either
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
implements these commands with a lot of convenience glue and presents a
simplified user interface to allow for the encryption of data with the
public ssh keys of the specified recipients, as well as the decryption
using the given private ssh key.


Supported Platforms
===================
jass(1) is written in Go, so it should run pretty much anywhere that you
can build a binary for.  (An older version of jass(1) written in shell is
also available in the 'src' directory.)

jass(1) was tested on the following systems:

- CentOS release 5 and 6
- Mac OS X 10.9.1
- NetBSD 6.0.1


How to install jass(1)
======================
jass(1) allows you to query LDAP for ssh keys.  If you are using this
feature, set the two LDAP* variables noted in the manual page.

Just copy the manual page from doc/jass.1 to somewhere in your MANPATH;
'go build src/jass.go' and copy the resulting binary somewhere in your
PATH.

The simplistic provided Makefile will copy those files under /usr/local or
wherever PREFIX points to if you run 'make install'.


How to use jass(1)
==================

Encrypting data
---------------
To encrypt the file service.yml for the local user jschauma and send it
via email:

    $ jass -u jschauma <service.yml | \
            mail -s "Please do the needful!" jschauma

If you do not have a user named 'jschauma' on your local systems, nor in
LDAP (if you set that up), then you can ask jass(1) to look that user's
key on GitHub by specifying the '-G' flag.

For example, to encrypt a message for Linus Torvalds, you might run:

    $ echo "0-day in ext4, ping me for details" | jass -G -u torvalds

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

Why don't we just use PGP?
--------------------------
Why indeed. PGP has many advantages and more widespread use would make
things a lot easier, but very few people appear to use it. If you're
interested in getting an introduction to PGP, I'll gladly come and give
you and your team a presentation.

Why does this ask me for my passphrase when decrypting? Can't it get it from my ssh agent?
------------------------------------------------------------------------------------------
Unfortunately the key available in any possible ssh agent cannot be used
by jass(1), since we are not actually using ssh(1) at all: we just happen to
use an ssh key.  If the key is encrypted, then we need to prompt the user
for the passphrase.

Who wrote this tool?
--------------------
jass(1) was originally written by Jan Schaumann (jschauma@netmeister.org) in
April 2013.

You can read more about it here:
* http://www.netmeister.org/blog/sharing-secrets-using-ssh-keys.html
* http://www.netmeister.org/blog/jass.html
* https://www.netmeister.org/blog/ssh2pkcs8.html
