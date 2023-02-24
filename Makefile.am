ACLOCAL_AMFLAGS         = -I m4
AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(atlas_measurementdir)
SUBDIRS = . probe-busybox/libevent-2.1.11-stable probe-busybox

SUBST_PATHS = sed \
             -e 's|@atlas_datadir[@]|$(atlas_datadir)|g' \
             -e 's|@atlas_execprefix[@]|$(atlas_execprefix)|g' \
             -e 's|@atlas_libexecdir[@]|$(atlas_libexecdir)|g' \
             -e 's|@atlas_measurementdir[@]|$(atlas_measurementdir)|g' \
             -e 's|@atlas_scriptsdir[@]|$(atlas_scriptsdir)|g' \
             -e 's|@atlas_rundir[@]|$(atlas_rundir)|g' \
             -e 's|@atlas_spooldir[@]|$(atlas_spooldir)|g' \
             -e 's|@atlas_sysconfdir[@]|$(atlas_sysconfdir)|g' \
             -e 's|@bindir[@]|$(bindir)|g' \
             -e 's|@datadir[@]|$(datadir)|g' \
             -e 's|@datarootdir[@]|$(datarootdir)|g' \
             -e 's|@docdir[@]|$(docdir)|g' \
             -e 's|@exec_prefix[@]|$(exec_prefix)|g' \
             -e 's|@includedir[@]|$(includedir)|g' \
             -e 's|@libdir[@]|$(libdir)|g' \
             -e 's|@libexecdir[@]|$(libexecdir)|g' \
             -e 's|@localedir[@]|$(localedir)|g' \
             -e 's|@localstatedir[@]|$(localstatedir)|g' \
             -e 's|@mandir[@]|$(mandir)|g' \
             -e 's|@prefix[@]|$(prefix)|g' \
             -e 's|@sbindir[@]|$(sbindir)|g' \
             -e 's|@sharedstatedir[@]|$(sharedstatedir)|g' \
             -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
             -e 's|@tmpdir[@]|$(tmpdir)|g'

sbin_SCRIPTS = \
               bin/ripe-atlas

atlas_scripts_SCRIPTS = \
                        atlas-config/etc/reg_servers.sh.dev \
                        atlas-config/etc/reg_servers.sh.prod \
                        atlas-config/etc/reg_servers.sh.test \
                        bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-ATLAS.sh \
                        bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-common.sh \
                        bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-reginit.sh \
                        bin/arch/linux/linux-functions.sh \
                        bin/array.lib.sh \
                        bin/atlas_log.lib.sh \
                        bin/class.lib.sh \
                        bin/json.lib.sh \
                        bin/paths.lib.sh \
                        bin/support.lib.sh \
                        bin/common.sh \
                        bin/common-pre.sh \
                        bin/config.sh \
                        bin/reginit.sh \
                        bin/resolvconf

atlas_data_DATA = \
                  atlas-config/etc/known_hosts.reg \
                  atlas-config/state/FIRMWARE_APPS_VERSION

CLEANFILES = \
             bin/paths.lib.sh \
             bin/common.sh \
             bin/common-pre.sh \
             bin/config.sh \
             bin/reginit.sh \
             bin/ripe-atlas \
             bin/resolvconf \
             probe-busybox/include/atlas_path.h

%.service:	%.service.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

%.h:	%.h.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

%.sh:	%.sh.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

bin/ripe-atlas:	bin/ripe-atlas.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

bin/resolvconf:	bin/resolvconf.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

atlas-config/state/FIRMWARE_APPS_VERSION:	atlas-config/state/FIRMWARE_APPS_VERSION.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

all-local:	probe-busybox/include/atlas_path.h bin/ripe-atlas.service

install-exec-local:
	$(mkinstalldirs) $(foreach dir,main 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20,$(DESTDIR)$(atlas_spooldir)/crons/$(dir))
	$(mkinstalldirs) $(foreach dir,new oneoff out/ooq out/ooq10,$(DESTDIR)$(atlas_spooldir)/data/$(dir))
	$(mkinstalldirs) $(DESTDIR)$(atlas_rundir)/status $(DESTDIR)$(atlas_rundir)/pids 
