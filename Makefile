all:
	@$(MAKE) -C src

install:
	@$(MAKE) -C src install

clean:
	@$(MAKE) -C src clean

config:
	@config/base.pl

.PHONY: all config install clean

