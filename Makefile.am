AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(prefix)/bb-13.3
SUBDIRS = probe-busybox/libevent-2.1.11-stable probe-busybox

DST_FILES = bin/ATLAS bin/common-pre.sh bin/common.sh bin/reginit.sh bin/arch/linux/linux-functions.sh \
	bin/arch/generic/generic-ATLAS.sh bin/arch/generic/generic-common.sh \
	bin/arch/generic/generic-reginit.sh bin/*.lib.sh

ATLAS_CONFIG_FILES = state/FIRMWARE_APPS_VERSION \
	etc/known_hosts.reg etc/reg_servers.sh.dev etc/reg_servers.sh.prod etc/reg_servers.sh.test

install-exec-local:	install-generic-config $(DST_FILES) $(ATLAS_CONFIG_FILES)

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(prefix)/{bin,bin/arch/generic,bin/arch/linux,bb-13.3,etc,lib,state}

# this target is used instead of bin_PROGRAMS because by using the automake variable (bin_PROGRAMS) the binaries listed are by default placed under the path defined by `bindir`. Therefore since the current software probe does not abide by the Linux FS hierarchy we manually force these files into a location that aligns with the current implementation (`/usr/local/atlas/bin`)
$(DST_FILES):	$(DESTDIR)$(prefix)/
	@echo "$@ ==> $<"
	@[[ -e $< ]] || (echo "some error for $<" && false)
	@mkdir -p $(dir $@)
	@cp -fr $@ $<$@

$(ATLAS_CONFIG_FILES):	$(DESTDIR)$(prefix)/
	@echo "$@ ==> $<"
	@[[ -e $< ]] || (echo "some error for $<" && false)
	@cp -fr atlas-config/$@ $<$@
