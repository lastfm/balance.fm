# $Id: Makefile,v 1.12 2010/12/03 12:49:15 t Exp $

#CFLAGS=-g -I.
CFLAGS=-O2 -Wall -Wstrict-prototypes -Wuninitialized

# uncomment for any OS other than Cygwin
BALANCE=balance
ROOT=root
INSTALL=install
BINDIR=/usr/sbin
MANDIR=${BINDIR}/../man/man1

# uncomment for Solaris:
# LIBRARIES=-lsocket -lnsl
# INSTALL=/usr/ucb/install
# BINDIR=/usr/local/libexec

# uncomment for Cygwin:
# LIBRARIES=-L/usr/local/lib -lcygipc
# BALANCE=balance.exe
# ROOT=Administrators

CC=gcc
RELEASE=3.54

all: balance 

balance: balance.o butils.o
	$(CC) $(CFLAGS) -I. -o balance balance.o butils.o $(LIBRARIES)

balance.o: balance.c balance.h
	$(CC) $(CFLAGS) -I. -c balance.c

butils.o: butils.c balance.h
	$(CC) $(CFLAGS) -I. -c butils.c

balance.pdf: balance.ps
	ps2pdf balance.ps balance.pdf	
		
balance.ps: balance.1
	troff -Tpost -man balance.1 | /usr/lib/lp/postscript/dpost > balance.ps
	# groff -f H -man balance.1 > balance.ps

ci:		
	ci -l *.c *.h Makefile balance.1 README balance.spec 

clean:
	rm -f $(BALANCE) *.o balance.ps balance.pdf

install:
	$(INSTALL) -o $(ROOT) -g $(ROOT) -m 755  $(BALANCE) \
		$(DESTDIR)$(BINDIR)/$(BALANCE) 
	$(INSTALL) -o $(ROOT) -g $(ROOT) -m 755  balance.1 \
		$(DESTDIR)$(MANDIR) 
	mkdir -p $(DESTDIR)/var/run/balance
	chmod 1777 $(DESTDIR)/var/run/balance

release: balance.pdf
	rm -rf ./releases/balance-$(RELEASE)
	mkdir ./releases/balance-$(RELEASE)
	cp balance.1 balance.pdf balance.c balance.h butils.c COPYING Makefile README ./releases/balance-$(RELEASE)
	cp balance.spec ./releases/balance-$(RELEASE)/balance.spec
	cd releases; tar -cvf balance-$(RELEASE).tar ./balance-$(RELEASE)
	cd releases; gzip balance-$(RELEASE).tar

rpm:	ever	
	cp releases/balance-$(RELEASE).tar.gz /usr/src/redhat/SOURCES/
	rpmbuild -ba balance.spec
	cp /usr/src/redhat/SRPMS/balance-$(RELEASE)-1.src.rpm ./releases
	cp /usr/src/redhat/RPMS/i386/balance-$(RELEASE)-1.i386.rpm ./releases

ever:

