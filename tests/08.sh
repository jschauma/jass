#! /bin/sh

. ./setup

NAME="handles KeyKeeper keys"

begin

echo "${MSG}" | ${JASS} -K -u ${USER} >/dev/null 2>>${STDERR}
if [ $? -gt 0 ]; then
	fail
fi

end

exit 0
