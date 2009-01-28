NAME=checkcerts
VERSION=0.1.3
DISTNAME=$(NAME)-$(VERSION)

all:
	./checkcerts.pl --tests *.t --certs *.pem
verbose:
	./checkcerts.pl -v --tests *.t --certs *.pem


dist: tardist

tardist: $(DISTNAME).tar.gz

$(DISTNAME).tar.gz: distdir
	tar -zcvf $(DISTNAME).tar.gz $(DISTNAME)
	rm -rf $(DISTNAME)

distdir:
	rm -rf $(DISTNAME)
	perl "-MExtUtils::Manifest=manicopy,maniread" \
		-e "manicopy(maniread(),'$(DISTNAME)', 'best');"
