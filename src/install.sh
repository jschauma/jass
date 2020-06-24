#! /bin/sh
#
# Originally written by Jan Schaumann
# <jschauma@netmeister.org> in June 2020.
#
# This script will attempt to fetch and install the
# jass binary and manual page from GitHub.

set -eu

NAME="jass"
_PREFIX="${PREFIX:-/usr/local}"

_FETCH="curl -s -o"
_GITHUB_URL="https://raw.githubusercontent.com/jschauma/${NAME}/master"
_UNAME="$(uname | tr '[A-Z]' '[a-z]')"
_UNAME_M="$(uname -m)"

_SUPPORTED_OS="darwin freebsd linux netbsd openbsd"
_SUPPORTED_ARCH="amd64 x86_64"

_TDIR="$(mktemp -d "${TMPDIR:-/tmp}/${NAME}.XXXX")"

###
### Functions
###

checkOS() {
	local archok=0
	local osok=0

	local arch fetch os

	for os in ${_SUPPORTED_OS}; do
		if [ x"${os}" = x"${_UNAME}" ]; then
			osok=1
			break
		fi
	done

	for arch in ${_SUPPORTED_ARCH}; do
		if [ x"${arch}" = x"${_UNAME_M}" ]; then
			archok=1
			break
		fi
	done

	if [ ${osok} -ne 1 ] || [ ${archok} -ne 1 ]; then
		echo "Unsupported OS (${_UNAME}) or architecture (${UNAME_M})." >&2
		echo "Please build ${NAME} yourself." >&2
		exit 1
		# NOTREACHED
	fi

	fetch="$(which curl || true)"
	if [ -z "${fetch}" ]; then
		fetch="$(which wget)"
		if [ -z "${fetch}" ]; then
			echo "Unable to find either curl(1) or wget(1)." >&2
			echo "Please ensure either one is found in your PATH." >&2
			exit 1
			# NOTREACHED
		fi
		_FETCH="wget -q -O"
	fi
}

cleanup() {
	rm -fr "${_TDIR}"
}

fetchFiles() {
	${_FETCH} "${_TDIR}/${NAME}.${_UNAME}" "${_GITHUB_URL}/binaries/${NAME}.${_UNAME}" || {
		echo "Unable to fetch '${_GITHUB_URL}/binaries/${NAME}.${_UNAME}'." >&2
		exit 1
		# NOTREACHED
	}
	${_FETCH} "${_TDIR}/${NAME}.1" "${_GITHUB_URL}/doc/${NAME}.1" || {
		echo "Unable to fetch '${_GITHUB_URL}/binaries/${NAME}.${_UNAME}'." >&2
		exit 1
		# NOTREACHED
	}
}

installFiles() {
        mkdir -p "${_PREFIX}/bin" "${_PREFIX}/share/man/man1"
        install -c -m 0555 "${_TDIR}/${NAME}.${_UNAME}" "${_PREFIX}/bin/${NAME}"
        install -c -m 0555 "${_TDIR}/${NAME}.1" "${_PREFIX}/share/man/man1/${NAME}.1"
}

###
### Main
###



trap 'cleanup' 0

checkOS
fetchFiles
installFiles
