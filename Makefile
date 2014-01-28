NAME=jass
VERSION=$(shell sed -n -e 's/^const VERSION = "\(.*\)"/\1/p' src/jass.go)

HOST="buildhost"
DSTROOT=osx/dstroot
PREFIX?=/usr/local

help:
	@echo "The following targets are available:"
	@echo "build      build the executable"
	@echo "clean      remove temporary build files"
	@echo "install    install ${NAME} into ${PREFIX}"
	@echo "osxpkg     create an OS X package of ${NAME}-${VERSION}"
	@echo "release    get everything ready for a new release"
	@echo "rpm        build an RPM of ${NAME}-${VERSION} on ${HOST}"
	@echo "sign       sign the RPM and OS X package"
	@echo "uninstall  uninstall ${NAME} from ${PREFIX}"

rpm: spec buildrpm

spec: rpm/${NAME}.spec

rpm/${NAME}.spec: rpm/${NAME}.spec.in
	cat $< CHANGES | sed -e "s/VERSION/${VERSION}/" >$@

build: src/${NAME}

src/${NAME}: src/${NAME}.go
	go build -o src/${NAME} src/${NAME}.go

buildrpm: packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm

packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm:
	@rsync -e ssh -avz . ${HOST}:${NAME}/.
	@ssh ${HOST} "cd ${NAME}/src && GOROOT=~/go ~/go/bin/go build jass.go && cd ../rpm && sh mkrpm.sh ${NAME}.spec"
	@scp ${HOST}:redhat/RPMS/*/${NAME}-${VERSION}-1.x86_64.rpm packages/rpms/
	@ls packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm

osxpkg: build bom archive dmg

dmg: osx/jass.dmg

osx/${NAME}.dmg: build
	cp -R osx/${NAME}.pkg osx/${NAME}-${VERSION}.pkg
	hdiutil create -volname Jass -srcfolder osx/${NAME}-${VERSION}.pkg -ov -format UDZO osx/${NAME}-${VERSION}.dmg
	cp osx/${NAME}-${VERSION}.dmg packages/dmgs/

osx/${NAME}-${VERSION}.dmg: osx/${NAME}.dmg

sign: osx/${NAME}-${VERSION}.dmg.asc packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm.asc

osx/${NAME}-${VERSION}.dmg.asc: osxpkg
	gpg -b -a osx/${NAME}-${VERSION}.dmg

packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm.asc: packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm
	gpg -b -a packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm

release: osx/${NAME}-${VERSION}.dmg.asc packages/rpms/${NAME}-${VERSION}-1.x86_64.rpm.asc
	cp osx/${NAME}-${VERSION}.dmg osx/${NAME}-${VERSION}.dmg.asc packages/dmgs/.
	cd packages/dmgs && ln -f ${NAME}-${VERSION}.dmg ${NAME}.dmg
	cd packages/dmgs && ln -f ${NAME}-${VERSION}.dmg.asc ${NAME}.dmg.asc
	echo ${VERSION} > packages/version

prep: .prepdone

.prepdone:
	umask 022 && mkdir -p ${DSTROOT}${PREFIX}/bin ${DSTROOT}${PREFIX}/share/man/man1
	install -c -m 0755 src/${NAME} ${DSTROOT}${PREFIX}/bin/${NAME}
	install -c -m 0644 doc/${NAME}.1 ${DSTROOT}${PREFIX}/share/man/man1/${NAME}.1
	mkdir -p osx/${NAME}.pkg/Contents/Resources
	install -c -m 644 README osx/${NAME}.pkg/Contents/Resources/ReadMe.txt
	install -c -m 644 LICENSE osx/${NAME}.pkg/Contents/Resources/License.txt
	sudo chown -R root:staff ${DSTROOT}
	touch .prepdone

archive: prep osx/${NAME}.pkg/Contents/Archive.pax.gz

osx/${NAME}.pkg/Contents/Archive.pax.gz:
	cd osx/dstroot && pax -w -x cpio . -f ../${NAME}.pkg/Contents/Archive.pax
	gzip osx/${NAME}.pkg/Contents/Archive.pax

bom: prep osx/${NAME}.pkg/Contents/Archive.bom

osx/${NAME}.pkg/Contents/Archive.bom:
	mkbom osx/dstroot osx/${NAME}.pkg/Contents/Archive.bom

install: build
	mkdir -p ${PREFIX}/bin ${PREFIX}/share/man/man1
	install -c -m 0555 src/${NAME} ${PREFIX}/bin/${NAME}
	install -c -m 0555 doc/${NAME}.1 ${PREFIX}/share/man/man1/${NAME}.1

uninstall:
	rm -f ${PREFIX}/bin/${NAME} ${PREFIX}/share/man/man1/${NAME}.1

clean:
	sudo rm -fr ${DSTROOT}
	rm -f src/jass
	rm -f .prepdone rpm/${NAME}.spec
	rm -f osx/${NAME}.dmg* osx/${NAME}-${VERSION}.dmg* osx/.DS_Store
	rm -f osx/${NAME}.pkg/Contents/Archive.bom
	rm -f osx/${NAME}.pkg/Contents/Archive.pax.gz
	rm -fr osx/${NAME}.pkg/Contents/Resources osx/${NAME}-${VERSION}.pkg
	rm -f packages/dmgs/${NAME}.dmg*
