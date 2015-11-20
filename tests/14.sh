#! /bin/sh

. ./setup

NAME="fp-path"

begin

nkey=${TDIR}/k

ssh-keygen -f ${nkey} -P '' -t rsa >/dev/null 2>>${STDERR}

output=$(echo "foo" | ${JASS} -k ${nkey}.pub |			\
		sed -e "s|${nkey}.pub|mumble-something-|"|	\
		${JASS} -d -k ${nkey})

if [ x"${output}" != x"foo" ]; then
	fail
fi

end

exit 0
