#! /bin/sh

. ./setup

NAME="handles GitHub keys"

if [ -z "${GITHUB_URL}" -a -z "${ALL}" ]; then
	echo "Skipping GitHub test..."
	exit 0
fi

begin

echo "${MSG}" | ${JASS} -u ${USER} >/dev/null 2>>${STDERR}
if [ $? -gt 0 ]; then
	fail
fi

end

exit 0
