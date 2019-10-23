#! /bin/sh

. ./setup

NAME="fail on tampered data"

begin

nkey=${TDIR}/k.XXX
out=${TDIR}/out
ssh-keygen -f ${nkey} -P '' -t rsa >/dev/null 2>${STDERR}

echo "${MSG}" | ${JASS} -k ${nkey}.pub >${out} 2>>${STDERR}
sed -e '/ message/ {n; s/^./X/;}' ${out} >${out}.t &&
	mv -f ${out}.t ${out}
${JASS} -k ${nkey} -d <${out} 2>&1 >/dev/null | grep -q "Incorrect HMAC! Aborting."

if [ $? -gt 0 ]; then
	fail
fi

end

rm -f ${nkey} ${nkey}.pub ${out}

exit 0
