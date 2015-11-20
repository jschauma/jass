#! /bin/sh

. ./setup

NAME="encrypt for a group we're not a member of"

if [ -n "${NO_LDAP}" -a -z "${ALL}" ]; then
	echo "Skipping LDAP group test..."
	exit 0
fi

begin

# This is a shoddy trick: we just guess that we are not a member of the
# 'exec' group.

group="exec"

OUT="$(echo "${MSG}" | ${JASS} -g ${group} 2>${STDERR} | ${JASS} -d ${JASS_FLAGS} 2>>${STDERR})"

if [ $? != 1 ]; then
	fail
else
	if ! grep -q "Data was not encrypted for the key " ${STDERR} ; then
		echo "Unexpected failure." >&2
		fail
	fi
fi

end

exit 0
