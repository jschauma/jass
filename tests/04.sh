#! /bin/sh

. ./setup

NAME="encrypt/decrypt for a local keypair"

begin

nkey=${TMPDIR:-/tmp}/k.XXX
ssh-keygen -f ${nkey} -P '' -t rsa >/dev/null 2>${STDERR}

OUT="$(echo "${MSG}" | ${JASS} -k ${nkey}.pub 2>>${STDERR} | ${JASS} -d -k ${nkey} 2>>${STDERR})"

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

rm -f ${nkey} ${nkey}.pub

exit 0
