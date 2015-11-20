#! /bin/sh

. ./setup

NAME="handles KeyKeeper keys"

if [ -z "${KEYKEEPER_URL}" -a -z "${ALL}" ]; then
	echo "Skipping KeyKeeper test..."
	exit 0
fi

begin

echo "${MSG}" | ${JASS} -u ${USER} >/dev/null 2>>${STDERR}
if [ $? -gt 0 ]; then
	fail
fi

end

exit 0
