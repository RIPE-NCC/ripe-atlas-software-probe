AM_MAKEFLAGS=CONFIG_PREFIX:=$(DESTDIR)$(prefix)/bb-13.3
SUBDIRS = probe-busybox/libevent-2.1.11-stable probe-busybox

DST_FILES = bin/ATLAS bin/common-pre.sh bin/common.sh bin/reginit.sh bin/arch/linux/linux-functions.sh \
	bin/arch/centos-sw-probe/centos-sw-probe-ATLAS.sh bin/arch/centos-sw-probe/centos-sw-probe-common.sh \
	bin/arch/centos-sw-probe/centos-sw-probe-reginit.sh

ATLAS_CONFIG_FILES = state/FIRMWARE_APPS_VERSION \
	etc/known_hosts.reg etc/reg_servers.sh.dev etc/reg_servers.sh.prod etc/reg_servers.sh.test

install-exec-local:	install-generic-config $(DST_FILES) $(ATLAS_CONFIG_FILES)

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(prefix)/{bin,bin/arch/centos-sw-probe,bin/arch/linux,bb-13.3,etc,lib,state}

$(DST_FILES):	$(DESTDIR)$(prefix)/
	@echo "$@ ==> $<"
	@[[ -e $< ]] || (echo "some error for $<" && false)
	@mkdir -p $(dir $@)
	@cp -fr $@ $<$@

$(ATLAS_CONFIG_FILES):	$(DESTDIR)$(prefix)/
	@echo "$@ ==> $<"
	@[[ -e $< ]] || (echo "some error for $<" && false)
	@cp -fr atlas-config/$@ $<$@
