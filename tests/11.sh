#! /bin/sh

. ./setup

NAME="passin:env"

begin

pass=abc123
nkey=${TDIR}/k
ssh-keygen -f ${nkey} -P ${pass} -t rsa >/dev/null 2>>${STDERR}

export PASSPHRASE=${pass}

${JASS} -d -p env:MOO -k ${nkey} >/dev/null 2>&1
if [ $? -ne 1 ]; then
	fail
fi

OUT=$(echo "${MSG}" | ${JASS} -k ${nkey}.pub | ${JASS} -d -p env:PASSPHRASE -k ${nkey})

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

exit 0
