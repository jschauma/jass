NAME=jass
VERSION=1.4

DSTROOT=osx/dstroot
PREFIX?=/usr/local

osxpkg: dmg

dmg: bom archive osx/jass.dmg

osx/jass.dmg:
	hdiutil create -volname Jass -srcfolder osx/${NAME}.pkg -ov -format UDZO osx/jass.dmg

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

install:
	mkdir -p ${PREFIX}/bin ${PREFIX}/share/man/man1
	install -c -m 0555 src/${NAME} ${PREFIX}/bin/${NAME}
	install -c -m 0555 doc/${NAME}.1 ${PREFIX}/share/man/man1/${NAME}.1

uninstall:
	rm -f ${PREFIX}/bin/${NAME} ${PREFIX}/share/man/man1/${NAME}.1

clean:
	sudo rm -fr ${DSTROOT}
	rm -f .prepdone
	rm -f osx/${NAME}.dmg osx/.DS_Store
	rm -f osx/${NAME}.pkg/Contents/Archive.bom
	rm -f osx/${NAME}.pkg/Contents/Archive.pax.gz
	rm -fr osx/${NAME}.pkg/Contents/Resources
