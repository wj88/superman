binary:
	#dpkg-buildpackage -A -uc

pkg:
	dpkg-buildpackage -A -uc

clean:
	rm -f ../superman_1.0_all.deb ../superman_1.0_all.changes

install:
	mkdir -p $(DESTDIR)/etc/superman
	cp configs/superman.conf $(DESTDIR)/etc/superman/superman.conf
	mkdir -p $(DESTDIR)/usr/src/superman-1.0.0
	cp configs/dkms.conf $(DESTDIR)/usr/src/superman-1.0.0/
	mkdir -p $(DESTDIR)/usr/src/superman-1.0.0/src
	cp ../src/*.c $(DESTDIR)/usr/src/superman-1.0.0/src/
	cp ../src/*.h $(DESTDIR)/usr/src/superman-1.0.0/src/
	cp ../kernel-module/Makefile $(DESTDIR)/usr/src/superman-1.0.0/
	sed -i 's/..\/src\//.\/src\//g' $(DESTDIR)/usr/src/superman-1.0.0/Makefile
	mkdir -p $(DESTDIR)/usr/src/superman-1.0.0/daemon
	cp ../daemon/Makefile $(DESTDIR)/usr/src/superman-1.0.0/daemon
	sed -i 's/^bash -c /# bash -c /' $(DESTDIR)/usr/src/superman-1.0.0/daemon/Makefile
	mkdir -p $(DESTDIR)/sbin
	cp scripts/supermand-down $(DESTDIR)/sbin
	cp scripts/supermand-up $(DESTDIR)/sbin
	cp scripts/supermank-down $(DESTDIR)/sbin
	cp scripts/supermank-up $(DESTDIR)/sbin
	cp scripts/superman-down $(DESTDIR)/sbin
	cp scripts/superman-up $(DESTDIR)/sbin
	mkdir -p $(DESTDIR)/etc/network
	cp scripts/superman-ifupdown $(DESTDIR)/etc/network/superman
	mkdir -p $(DESTDIR)/etc/network/if-down.d
	mkdir -p $(DESTDIR)/etc/network/if-up.d
	ln -rs $(DESTDIR)/etc/network/superman $(DESTDIR)/etc/network/if-down.d/superman
	ln -rs $(DESTDIR)/etc/network/superman $(DESTDIR)/etc/network/if-up.d/superman
	mkdir -p $(DESTDIR)/lib/systemd/system
	cp configs/superman.service $(DESTDIR)/lib/systemd/system
