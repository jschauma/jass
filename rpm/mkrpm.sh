#!/bin/sh
#
# A silly little helper script to build the RPM.
set -e

for dir in BUILD RPMS SOURCES SPECS SRPMS; do
	dir="${HOME}/redhat/${dir}"
	test -d "${dir}" || mkdir -p "${HOME}/redhat/${dir}"
done

name=${1:?"Usage: build <toolname>"}
name=${name%.spec}
#topdir=$(rpm --eval "%{_topdir}")
topdir="${HOME}/redhat"
sourcedir="${topdir}/SOURCES"
version=$(awk '/define version/ { print $NF }' ${name}.spec)
tdir=${TMPDIR:-/tmp}/${USER}/${name}-${version}
buildroot="${topdir}/BUILD/${name}-${version}-root"
mkdir -p ${tdir}
echo "=> Copying sources..."
( cd .. && tar cf - . | tar xf - -C ${tdir}/ )
echo "=> Creating source tarball under ${sourcedir}..."
( cd ${tdir}/.. && tar zcf ${sourcedir}/${name}-${version}.tar.gz ${name}-${version} )
echo "=> Building RPM..."
#rpmbuild --define "_gpg_name <KEYID>" --sign --quiet --buildroot ${buildroot} --clean -bb ${name}.spec
#rpmbuild --quiet --buildroot ${buildroot} --clean -bb ${name}.spec
rpmbuild --quiet --define "_topdir ${topdir}" --buildroot ${buildroot} --clean -bb ${name}.spec
rpm="$(find ${topdir} -name '*rpm' -newer ${sourcedir}/${name}-${version}.tar.gz -print)"
echo "=> RPM built: ${rpm}"
rm -fr "${tdir}"
