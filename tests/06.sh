#! /bin/sh

. ./setup

NAME="encrypt 'large' amount of data"

begin

note "This may take a moment."

nkey=${TDIR}/k
ssh-keygen -f ${nkey} -P '' -t rsa >/dev/null 2>>${STDERR}

#dd if=/dev/zero bs=1024 count=1048576 2>${STDERR}	| \
dd if=/dev/zero bs=1024 count=10240 2>${STDERR}	| \
	${JASS} -k ${nkey}.pub 2>>${STDERR}		| \
	${JASS} -d -k ${nkey} >/dev/null 2>>${STDERR}
if [ $? -gt 0 ]; then
	fail
fi

end

exit 0
