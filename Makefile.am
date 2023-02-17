ACLOCAL_AMFLAGS         = -I m4
AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(atlas_measurementdir)
SUBDIRS = probe-busybox/libevent-2.1.11-stable probe-busybox

DST_FILES = bin/arch/linux/linux-functions.sh \
            bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-ATLAS.sh \
            bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-common.sh \
            bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-reginit.sh

A_SCRIPTS_PATH := arch/$(probe_scripts_path)/
A_LINUX_PATH := arch/linux/
A_ATLAS_CONFIG := atlas-config/
A_STATE_PATH := state
A_ETC_PATH := etc
SH_FINALISE = sed \
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
     
atlas_scripts_SCRIPTS = bin/array.lib.sh \
                        bin/atlas_log.lib.sh \
                        bin/class.lib.sh \
                        bin/json.lib.sh \
                        bin/paths.lib.sh \
                        bin/support.lib.sh \
                        bin/common.sh \
                        bin/common-pre.sh \
                        bin/reginit.sh

CLEANFILES = bin/paths.lib.sh \
             bin/common.sh \
             bin/common-pre.sh \
             bin/reginit.sh

A_BIN_FILES := bin/ATLAS
A_SCRIPTS_FILES := bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-ATLAS.sh bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-common.sh bin/arch/$(probe_scripts_path)/$(probe_scripts_path)-reginit.sh
A_LINUX_FILES := bin/arch/linux/linux-functions.sh

A_CONFIG_FILES_STATE := $(A_ATLAS_CONFIG)$(A_STATE_PATH)/FIRMWARE_APPS_VERSION
A_CONFIG_FILES_ETC := $(A_ATLAS_CONFIG)$(A_ETC_PATH)/known_hosts.reg $(A_ATLAS_CONFIG)$(A_ETC_PATH)/reg_servers.sh.dev $(A_ATLAS_CONFIG)$(A_ETC_PATH)/reg_servers.sh.prod $(A_ATLAS_CONFIG)$(A_ETC_PATH)/reg_servers.sh.test

install-exec-local:	install-generic-filesystem install-local-filesystem install-ripe-atlas-bin install-ripe-atlas-generic install-ripe-atlas-linux \
	install-ripe-atlas-config-state install-ripe-atlas-config-etc

%.sh:	%.sh.in
	@rm -f $@
	$(AM_V_GEN)$(SH_FINALISE) $< > $@

install-data-hook:	install-symlinks

install-generic-filesystem:
	$(mkinstalldirs) $(DESTDIR)$(prefix)/{bin,bin/${A_SCRIPTS_PATH},bin/${A_LINUX_PATH},etc,state}

install-local-filesystem:
	$(mkinstalldirs) $(foreach dir,main 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20,$(DESTDIR)$(atlas_spooldir)/crons/$(dir))
	$(mkinstalldirs) $(foreach dir,new oneoff out/ooq out/ooq10,$(DESTDIR)$(atlas_spooldir)/data/$(dir))
	$(mkinstalldirs) $(DESTDIR)$(atlas_rundir)/status $(DESTDIR)$(atlas_rundir)/pids $(DESTDIR)$(atlas_datadir)/state

install-symlinks:
	$(LN_S) $(DESTDIR)$(prefix)/state/FIRMWARE_APPS_VERSION $(DESTDIR)$(atlas_datadir)/state/FIRMWARE_APPS_VERSION

# this target is used instead of bin_PROGRAMS because by using the automake variable (bin_PROGRAMS) the binaries listed are by default placed under the path defined by `bindir`. Therefore since the current software probe does not abide by the Linux FS hierarchy we manually force these files into a location that aligns with the current implementation (`/usr/local/atlas/bin`)
install-ripe-atlas-bin: $(DESTDIR)$(bindir)
	$(mkinstalldirs) $<
	install -m 0755 -t $< $(A_BIN_FILES)

install-ripe-atlas-generic: $(DESTDIR)$(bindir)/$(A_SCRIPTS_PATH)
	$(mkinstalldirs) $<
	install -m 0755 -t $< $(A_SCRIPTS_FILES)

install-ripe-atlas-linux: $(DESTDIR)$(bindir)/$(A_LINUX_PATH)
	$(mkinstalldirs) $<
	install -m 0755 -t $< $(A_LINUX_FILES)

install-ripe-atlas-config-state: $(DESTDIR)$(prefix)/$(A_STATE_PATH)
	$(mkinstalldirs) $<
	install -m 0755 -t $< $(A_CONFIG_FILES_STATE)

install-ripe-atlas-config-etc: $(DESTDIR)$(prefix)/$(A_ETC_PATH)
	$(mkinstalldirs) $<
	install -m 0755 -t $< $(A_CONFIG_FILES_ETC)
