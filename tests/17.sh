#! /bin/sh

. ./setup

NAME="encrypted local key"

begin

nkey=${TDIR}/k.XXX
out=${TDIR}/out
ssh-keygen -f ${nkey} -P 'foo' -t rsa >/dev/null 2>${STDERR}

out=$(echo "${MSG}" | ${JASS} -k ${nkey}.pub 2>>${STDERR} | \
	${JASS} -p pass:foo -d -k ${nkey})

if [ $? -gt 0 ]; then
	fail
fi

if [ x"${out}" != x"${MSG}" ]; then
	fail
fi

end

rm -f ${nkey} ${nkey}.pub ${out}

exit 0
