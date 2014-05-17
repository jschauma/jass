#! /bin/sh

. ./setup

HOST="nest1.twitter.biz"
NAME="compatible with whatever is on ${HOST}"

begin

nkey=${TDIR}/k
ssh-keygen -f ${nkey} -P '' -t rsa >/dev/null 2>>${STDERR}

scp -q ${nkey} ${nkey}.pub ${HOST}:/tmp/ 2>>${STDERR}
OUT="$(echo "${MSG}" | ssh ${HOST} "jass -k /tmp/k.pub && rm /tmp/k.pub" 2>>${STDERR} | ${JASS} -d -k ${nkey} 2>>${STDERR} )"

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

OUT="$(echo "${MSG}" | ${JASS} -k ${nkey}.pub | ssh ${HOST} "jass -d -k /tmp/k && rm -f /tmp/k" 2>>${STDERR} )"

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

exit 0
