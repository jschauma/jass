#! /bin/sh

. ./setup

NAME="list"

begin

nkey=${TDIR}/k

ssh-keygen -f ${nkey} -P '' -t rsa >/dev/null 2>>${STDERR}

loutput=$(echo "foo" | ${JASS} -k ${nkey}.pub | ${JASS} -l)
fp=$(ssh-keygen -l -f ${nkey} | awk '{print $2}')

if [ x"${loutput}" != x"${nkey}.pub-${fp}" ]; then
	fail
fi

end

exit 0
