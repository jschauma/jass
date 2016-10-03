Quick Summary
=============
jass(1) is a tool to let you encrypt/decrypt data using SSH keys.  Keys
can be provided locally, fetched from LDAP, or retrieved from GitHub or
another external keyserver.

Please see below for further details.

Installing jass
---------------

If you run an x86-64 based RPM based Linux version, you can download an
RPM of jass(1) from [here](https://www.netmeister.org/apps/jass-4.1-1.x86_64.rpm)
([gpg signature](https://www.netmeister.org/apps/jass-4.1-1.x86_64.rpm.asc)).

If you run OS X, you can download a DMG installer from
[here](https://www.netmeister.org/apps/jass-4.1.dmg) ([gpg
signature](https://www.netmeister.org/apps/jass-4.1.dmg.asc)).

The PGP signatures are created using [this PGP
key](https://pgp.mit.edu/pks/lookup?op=get&search=0x66CE4FE96F6BD3D7).

If you want to build jass(1) yourself, you can run:
```
git clone https://github.com/jschauma/jass.git
cd jass
make install
```

This will copy the binary and manual page under /usr/local or wherever
PREFIX points to.


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

jass(1) does just that.  It supports encryption for multiple keys and
should generally be reasonably "user friendly".


Supported Platforms
===================
jass(1) is written in Go, so it should run pretty much anywhere that you
can build a binary for.  (An older version of jass(1) written in shell is
also available in the 'src' directory.)

jass(1) was tested on the following systems:

- CentOS release 5 and 6
- RedHat Enterprise Linux 6.5
- Mac OS X 10.10.3
- NetBSD 6.0.1

Finding keys
============
You can specify the public key(s) to encrypt data for on the command-line.
Alternatively, jass(1) can try to fetch the key(s) for a given user or
members of a Unix group from LDAP or a keyserver.

You can specify the default method in the sources prior to building
jass(1); support for a configuration file may be added in the future.

KeyKeeper Server
----------------
jass(1) can query a "KeyKeeper" server to retrieve public SSH keys.  When
doing so, it expects the server to respond with JSON data in the format
of:

```
{
  "result" : {
    "keys" : {
      "key" : [
        {
          "trust"     : "string",
          "content"   : "ssh-rsa AAAAB3NzaC1...",
          "sudo"      : "string",
          "type"      : "string",
          "validated" : "string",
          "api"       : "string"
        },
        ...
      ]
    },
    "status" : "string",
    "user"   : "string"
  }
}
```

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
key on GitHub by specifying the '-G' flag:

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
