#! /bin/sh

. ./setup

NAME="passin:pass"

begin

pass=abc123
nkey=${TDIR}/k
ssh-keygen -f ${nkey} -P ${pass} -t rsa >/dev/null 2>>${STDERR}

${JASS} -d -p pass: -k ${nkey} >/dev/null 2>&1
if [ $? -ne 1 ]; then
	fail
fi

OUT=$(echo "${MSG}" | ${JASS} -k ${nkey}.pub | ${JASS} -d -p pass:${pass} -k ${nkey})

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

exit 0
