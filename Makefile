CFLAGS=-O2 -g -Wall -Wextra -Wstrict-prototypes -pedantic -std=gnu99

# uncomment for any OS other than Cygwin
BALANCE=balance.fm
ROOT=root
INSTALL=install
BINDIR=/usr/sbin
MANDIR=${BINDIR}/../man/man1
BALANCEEXE=$(BALANCE)

# uncomment for Solaris:
# LIBRARIES=-lsocket -lnsl
# INSTALL=/usr/ucb/install
# BINDIR=/usr/local/libexec

# uncomment for Cygwin:
# LIBRARIES=-L/usr/local/lib -lcygipc
# BALANCEEXE=$(BALANCE).exe
# ROOT=Administrators

CC=gcc
RELEASE=1.0.0

all: $(BALANCEEXE)

$(BALANCEEXE): balance.o butils.o
	$(CC) $(CFLAGS) -I. -o $(BALANCEEXE) balance.o butils.o $(LIBRARIES)

balance.o: balance.c balance.h
	$(CC) $(CFLAGS) -I. -c balance.c

butils.o: butils.c balance.h
	$(CC) $(CFLAGS) -I. -c butils.c

$(BALANCE).html: $(BALANCE).1
	man2html ./$(BALANCE).1 >$(BALANCE).html

$(BALANCE).dvi: $(BALANCE).1
	man2dvi ./$(BALANCE).1 >$(BALANCE).dvi

$(BALANCE).pdf: $(BALANCE).dvi
	dvipdf $(BALANCE).dvi $(BALANCE).pdf

$(BALANCE).ps: $(BALANCE).1
	troff -Tpost -man $(BALANCE).1 | /usr/lib/lp/postscript/dpost > $(BALANCE).ps
	# groff -f H -man $(BALANCE).1 > $(BALANCE).ps

clean:
	rm -f $(BALANCE) *.o $(BALANCE).dvi $(BALANCE).html $(BALANCE).ps $(BALANCE).pdf

install:
	mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -o $(ROOT) -g $(ROOT) -m 755  $(BALANCEEXE) \
		$(DESTDIR)$(BINDIR)/$(BALANCEEXE)
	mkdir -p $(DESTDIR)$(MANDIR)
	$(INSTALL) -o $(ROOT) -g $(ROOT) -m 755  $(BALANCE).1 \
		$(DESTDIR)$(MANDIR)
	mkdir -p $(DESTDIR)/var/run/$(BALANCE)
	chmod 1777 $(DESTDIR)/var/run/$(BALANCE)

release: $(BALANCE).pdf
	rm -rf ./releases/$(BALANCE)-$(RELEASE)
	mkdir ./releases/$(BALANCE)-$(RELEASE)
	cp $(BALANCE).1 $(BALANCE).pdf balance.c balance.h butils.c COPYING Makefile README ./releases/$(BALANCE)-$(RELEASE)
	cp $(BALANCE).spec ./releases/$(BALANCE)-$(RELEASE)/$(BALANCE).spec
	cd releases; tar -cvf $(BALANCE)-$(RELEASE).tar ./$(BALANCE)-$(RELEASE)
	cd releases; gzip $(BALANCE)-$(RELEASE).tar

rpm: ever
	cp releases/$(BALANCE)-$(RELEASE).tar.gz /usr/src/redhat/SOURCES/
	rpmbuild -ba $(BALANCE).spec
	cp /usr/src/redhat/SRPMS/$(BALANCE)-$(RELEASE)-1.src.rpm ./releases
	cp /usr/src/redhat/RPMS/i386/$(BALANCE)-$(RELEASE)-1.i386.rpm ./releases

ever:

