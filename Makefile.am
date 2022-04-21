ACLOCAL_AMFLAGS         = -I m4
AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(prefix)/bb-13.3
SUBDIRS = probe-busybox/libevent-2.1.11-stable probe-busybox

DST_FILES = bin/ATLAS bin/common-pre.sh bin/common.sh bin/reginit.sh bin/arch/linux/linux-functions.sh \
	bin/arch/$(probe_type)/$(probe_type)-ATLAS.sh bin/arch/$(probe_type)/$(probe_type)-common.sh \
	bin/arch/$(probe_type)/$(probe_type)-reginit.sh bin/*.lib.sh

A_SCRIPTS_PATH := arch/$(probe_type)/
A_LINUX_PATH := arch/linux/
A_ATLAS_CONFIG := atlas-config/
A_STATE_PATH := state
A_ETC_PATH := etc

A_BIN_FILES := bin/ATLAS bin/common-pre.sh bin/common.sh bin/reginit.sh bin/*.lib.sh
A_SCRIPTS_FILES := bin/arch/$(probe_type)/$(probe_type)-ATLAS.sh bin/arch/$(probe_type)/$(probe_type)-common.sh bin/arch/$(probe_type)/$(probe_type)-reginit.sh
A_LINUX_FILES := bin/arch/linux/linux-functions.sh

A_CONFIG_FILES_STATE := $(A_ATLAS_CONFIG)$(A_STATE_PATH)/FIRMWARE_APPS_VERSION
A_CONFIG_FILES_ETC := $(A_ATLAS_CONFIG)$(A_ETC_PATH)/known_hosts.reg $(A_ATLAS_CONFIG)$(A_ETC_PATH)/reg_servers.sh.dev $(A_ATLAS_CONFIG)$(A_ETC_PATH)/reg_servers.sh.prod $(A_ATLAS_CONFIG)$(A_ETC_PATH)/reg_servers.sh.test

install-exec-local:	install-generic-filesystem install-local-filesystem install-ripe-atlas-bin install-ripe-atlas-generic install-ripe-atlas-linux \
	install-ripe-atlas-config-state install-ripe-atlas-config-etc

install-data-hook:	install-symlinks

install-generic-filesystem:
	$(mkinstalldirs) $(DESTDIR)$(prefix)/{bin,bin/$(A_SCRIPTS_PATH),bin/$(A_LINUX_PATH),bb-13.3,etc,state}

install-local-filesystem:
	$(mkinstalldirs) $(DESTDIR)$(working_dir)/{bin,crons/{main,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20},data/{new,oneoff,out/ooq,out/ooq10},run,state}

install-symlinks:
	$(LN_S) $(DESTDIR)$(prefix)/state/FIRMWARE_APPS_VERSION $(DESTDIR)$(working_dir)/state/FIRMWARE_APPS_VERSION

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
