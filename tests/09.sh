#! /bin/sh

. ./setup

NAME="handles GitHub keys"

begin

echo "${MSG}" | ${JASS} -G -u ${USER} >/dev/null 2>>${STDERR}
if [ $? -gt 0 ]; then
	fail
fi

end

exit 0
