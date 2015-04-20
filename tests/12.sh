#! /bin/sh

. ./setup

NAME="passin:file"

begin

pass=abc123
nkey=${TDIR}/k
passfile=${TDIR}/f

echo "${pass}" >${passfile}

ssh-keygen -f ${nkey} -P ${pass} -t rsa >/dev/null 2>>${STDERR}

${JASS} -d -p file:/does/not/exist -k ${nkey} >/dev/null 2>&1
if [ $? -ne 1 ]; then
	fail
fi

OUT=$(echo "${MSG}" | ${JASS} -k ${nkey}.pub | ${JASS} -d -p file:${passfile} -k ${nkey})

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

exit 0
