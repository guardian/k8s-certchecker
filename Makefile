.PHONY: certchecker test clean docker

all: certchecker webserver

certchecker:
	make -C certchecker/

webserver:
	make -C webserver/

test:
	make -C certchecker/ test
	make -C webserver/ test

clean:
	make -C certchecker/ clean
	make -C webserver/ clean

docker:
	make -C certchecker/ docker
	make -C webserver/ docker