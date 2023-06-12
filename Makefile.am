include $(top_srcdir)/rules.mk

ACLOCAL_AMFLAGS         = -I m4
AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(atlas_measurementdir)
SUBDIRS = bin atlas-config probe-busybox/libevent-2.1.11-stable probe-busybox .

install-exec-local:
	$(mkinstalldirs) $(foreach dir,main 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20,$(DESTDIR)$(atlas_spooldir)/crons/$(dir))
	$(mkinstalldirs) $(foreach dir,new oneoff out/ooq out/ooq10,$(DESTDIR)$(atlas_spooldir)/data/$(dir))
	$(mkinstalldirs) $(DESTDIR)$(atlas_rundir)/status $(DESTDIR)$(atlas_rundir)/pids 
	$(mkinstalldirs) $(DESTDIR)$(atlas_sysconfdir)
