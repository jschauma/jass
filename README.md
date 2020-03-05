Quick Summary
=============
jass(1) is a tool to let you encrypt/decrypt data using SSH keys.  Keys
can be provided locally, fetched from LDAP, or retrieved from GitHub or
another external keyserver.

Encryption:

    $ jass -u jschauma <service.yml | \
            mail -s "Please do the needful!" jschauma

Decryption:

    jass -d -k ~/.ssh/privkey <secret

Please see the
[manual page](https://github.com/jschauma/jass/blob/master/doc/jass.txt)
for further details.

Installation
============

If you're on Mac OS X, you can install [this
package](https://github.com/jschauma/jass/raw/master/packages/dmgs/jass.dmg);
that package is signed with my PGP key
[6F6BD3D7](https://www.netmeister.org/public_key.gpg.asc)
with the signature
[here](https://github.com/jschauma/jass/raw/master/packages/dmgs/jass.dmg.asc).

```
$ cd packages/dmgs
$ gpg --verify jass.dmg.asc jass.dmg
gpg: Signature made Wed Oct 23 16:55:04 2019 EDT using RSA key ID 6F6BD3D7
gpg: Good signature from "Jan Schaumann <jschauma@netbsd.org>"
gpg:                 aka "Jan Schaumann (@jschauma) <jschauma@netmeister.org>"
gpg:                 aka "Jan Schaumann <jschauma@netmeister.org>"
$ hdiutil mount -quiet jass.dmg
$ sudo installer -pkg /Volumes/Jass/jass-6.0.pkg -target /
installer: Package name is jass-6.0
installer: Upgrading at base path /
installer: The upgrade was successful.
$ hdiutil unmount /Volumes/Jass
"/Volumes/Jass" unmounted successfully.
$
```

### Manual installation

```
$ make build
```

If you like, you can install the binary and the manual
page somewhere convenient; the Makefile defaults to
'/usr/local' but you can change the PREFIX:

```
$ make PREFIX=~ install
```


Details
========

Sharing Secrets
---------------
Every now and then we have a need to share a "secret" with some
co-workers.  Coordinating this can be problematic, since you would either
need to be in the same physical space at the same time, or you would need
to be able to talk over the phone (and know that who you're talking to is
in fact the person you think you're talking to) etc. etc.

Wouldn't it be nice if you could just attach the file in question to an
email, insert it into a ticketing system, or drop it on a shared host?

Using SSH Keys
--------------
Many organizations already use SSH keys for access to their hosts. That is,
you have a central place (local file systems on shared hosts as well as,
perhaps, LDAP) where you have public keys that you already trust to belong
to the given person.  Most engineers are familiar with ssh(1) and the use
of ssh keys for authentication, but what not everybody might be aware of
is that by their very nature these keys can also be used for encryption of
non-SSH related data.

jass(1) does just that.  It supports encryption for multiple keys and
should generally be reasonably "user friendly".

Finding keys
------------
You can specify the public key(s) to encrypt data for on the command-line.
Alternatively, jass(1) can try to fetch the key(s) for a given user or
members of a Unix group from LDAP or a keyserver.

You can specify the default method in the sources prior to building
jass(1); support for a configuration file may be added in the future.

GitHub Service
--------------
By default, jass(1) will look for keys for the recipients on GitHub.  It
does so by retrieving the URL `https://api.github.com/users/<user>/keys`.
If you prefer this not to happen, set the GITHUB_URL environment variable
to the empty string.

Alternatively, you can set GITHUB_URL to e.g., an internal GitHub service
endpoint such as `https://git.your.domain.com/api/v3`,
and jass(1) will look for keys there.  This also will
work for specifying a GitHub "team" instead of a
group, either in the format "org/team" or as a numeric
team-id.

If you are using an internal GitHub service and require authentication,
you can set the GITHUB_API_TOKEN environment variable to enable
Basic HTTP Auth.   This token will require `read:org`
and `read:user` privileges.


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

For example, to encrypt a message for Linus Torvalds
using his GitHub key, you might run:

    $ echo "0-day in ext4, ping me for details" | jass -u torvalds

Please see the [manual page](https://github.com/jschauma/jass/blob/master/doc/jass.txt)
for details and other examples.

Decrypting data
---------------
To decrypt data, you need to have access to the private ssh key in
question. This means that this should not happen on a shared box but
instead is likely to occur on your desktop, laptop or other private
system:

    jass -d -k ~/.ssh/privkey <secret


Supported Platforms
-------------------
jass(1) is written in Go, so it should run pretty much anywhere that you
can build a binary for.  (An older version of jass(1) written in shell is
also available in the 'src' directory.)

jass(1) was tested on the following systems:

- RedHat Enterprise Linux 6.8
- Mac OS X 10.15.2
- NetBSD 8.0

FAQ
===

Why don't you just use PGP?
--------------------------
Why indeed. PGP has many advantages and more widespread use would make
things a lot easier, but very few people appear to use it.  SSH keys,
on the other hand, are used nearly everywhere.

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
