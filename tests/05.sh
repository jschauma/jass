#! /bin/sh

. ./setup

NAME="fail on invalid key"

begin

nkey=${TMPDIR:-/tmp}/k.XXX
ssh-keygen -f ${nkey} -P '' -t dsa >/dev/null 2>${STDERR}

OUT="$(echo "${MSG}" | ${JASS} -k ${nkey}.pub 2>>${STDERR})"

if [ $? -lt 1 ]; then
	fail
fi

end

rm -f ${nkey} ${nkey}.pub

exit 0
