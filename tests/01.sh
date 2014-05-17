#! /bin/sh

. ./setup

NAME="single user encrypt/decrypt"

begin

OUT="$(echo "${MSG}" | ${JASS} -u ${USER} 2>${STDERR} | ${JASS} -d ${JASS_FLAGS} 2>>${STDERR} )"

if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

exit 0
