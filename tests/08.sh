#! /bin/sh

. ./setup

NAME="handles KeyKeeper keys"

begin

echo "${MSG}" | env KEYKEEPER_URL="https://keykeeper/api/keys?user=<user>" ${JASS} -u ${USER} >/dev/null 2>>${STDERR}
if [ $? -gt 0 ]; then
	fail
fi

end

exit 0
