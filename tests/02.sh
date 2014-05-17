#! /bin/sh

. ./setup

NAME="encrypt for a group"

begin

note "This may take a while."

group=$(ldaps uid=${USER} twmemberOf | sed -n -e 's/^twmemberOf: cn=\([^,]*\),.*/\1/p' | head -2 | tail -1)

OUT="$(echo "${MSG}" | ${JASS} -g ${group} 2>${STDERR} | ${JASS} -d ${JASS_FLAGS} 2>>${STDERR})"
if [ x"${OUT}" != x"${MSG}" ]; then
	fail
fi

end

exit 0
