PREFIX?=/usr/local

install:
	mkdir -p ${PREFIX}/bin ${PREFIX}/share/man/man1
	install -c -m 0555 src/jass ${PREFIX}/bin/jass
	install -c -m 0555 doc/jass.1 ${PREFIX}/share/man/man1/jass.1

uninstall:
	rm -f ${PREFIX}/bin/jass ${PREFIX}/share/man/man1/jass.1
