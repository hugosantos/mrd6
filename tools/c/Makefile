CFLAGS ?= -g -O2
CFLAGS += -Wall -ansi

PREFIX ?= /usr/local

-include ../../src/Makefile.options

all: mrd6sh

install: mrd6sh
	install -D mrd6sh $(DESTDIR)$(PREFIX)/bin/mrd6sh

clean:
	rm -f mrd6sh

