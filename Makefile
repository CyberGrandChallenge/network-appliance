MAN_DIR      = $(DESTDIR)/usr/share/man/man1
BIN_DIR      = $(DESTDIR)/usr/bin
SHARE_DIR    = $(DESTDIR)/usr/share/cgc-network-appliance
PYLIB_DIR    = $(DESTDIR)/usr/lib/python2.7/dist-packages/ids
BINS		 = $(wildcard bin/*)
EXTRA		 = $(wildcard extra/*)
EXAMPLES 	 = $(wildcard examples/*.rules)

MAN			 = $(addsuffix .1.gz,$(notdir $(BINS)))

all: man

man: $(MAN)

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

install:
	install -d $(BIN_DIR)
	install -d $(MAN_DIR)
	install -d $(SHARE_DIR)
	install -d $(SHARE_DIR)/extra
	install -d $(SHARE_DIR)/examples
	install -d $(PYLIB_DIR)
	install -m 755 $(BINS) $(BIN_DIR)
	install -m 444 $(EXTRA) $(SHARE_DIR)/extra
	install -m 444 $(EXAMPLES) $(SHARE_DIR)/examples
	install -m 444 ids/*.py $(PYLIB_DIR)
	install $(MAN) $(MAN_DIR)

clean:
	rm -f *.1.gz *.tmp
