.SUFFIXES: .txt .1

all: jass.txt

.1.txt:
	nroff -man $< | col -b >$@

clean:
	rm -f jass.txt
