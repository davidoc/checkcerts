all:
	./checkcerts.pl --tests *.t --certs *.pem
verbose:
	./checkcerts.pl -v --tests *.t --certs *.pem
