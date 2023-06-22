include $(top_srcdir)/rules.mk

ACLOCAL_AMFLAGS         = -I m4
AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(atlas_measurementdir)
SUBDIRS = bin atlas-config probe-busybox/libevent-2.1.11-stable probe-busybox .

ATLAS_SPOOL_DIRS = \
		$(foreach dir,new oneoff out/ooq out/ooq10,$(DESTDIR)$(atlas_spooldir)/data/$(dir)) \
		$(foreach dir,main 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20,$(DESTDIR)$(atlas_spooldir)/crons/$(dir))

ATLAS_RUN_DIRS = \
		$(foreach dir,status pids,$(DESTDIR)$(atlas_rundir)/$(dir))

ATLAS_CONF_DIRS = \
		$(DESTDIR)/$(atlas_sysconfdir)

if DO_CHOWN
ATLAS_OWN_MEAS_OPTS = \
		-o $(ripe_atlas_measurement) \
		-g $(ripe_atlas_group)
ATLAS_OWN_CONF_OPTS = \
		-o $(ripe_atlas_user) \
		-g $(ripe_atlas_group)
ATLAS_OWN_SUID_OPTS = \
		-m 4750
else
ATLAS_OWN_CONF_OPTS =
ATLAS_OWN_MEAS_OPTS =
ATLAS_OWN_SUID_OPTS =
endif

install-exec-local:
	$(mkinstalldirs) -m 0755 $(ATLAS_OWN_MEAS_OPTS) $(ATLAS_SPOOL_DIRS)
	$(mkinstalldirs) -m 0770 $(ATLAS_OWN_CONF_OPTS) $(ATLAS_CONF_DIRS)
if !SYSTEMD_INSTALL
	$(mkinstalldirs) -m 0775 $(ATLAS_OWN_MEAS_OPTS) $(ATLAS_RUN_DIRS)
endif

#
# Technically this hack belongs in probe-busybox, but it is here
# because busybox is a different build system.
install-exec-hook:
	$(install_sh) $(ATLAS_OWN_SUID_OPTS) $(ATLAS_OWN_MEAS_OPTS) $(top_srcdir)/probe-busybox/busybox_unstripped $(DESTDIR)/$(atlas_measurementdir)/busybox
if SETCAP_INSTALL
	setcap cap_net_raw=ep $(DESTDIR)$(atlas_measurementdir)/busybox
endif
