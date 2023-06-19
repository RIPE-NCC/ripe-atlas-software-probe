include $(top_srcdir)/rules.mk

atlas_scripts_SCRIPTS = \
                        common/reg_servers.sh.dev \
                        common/reg_servers.sh.test

atlas_data_DATA = \
                  common/FIRMWARE_APPS_VERSION \
		  common/measurement.conf

if INSTALL_MODE_probe
atlas_data_DATA += \
			probe/known_hosts.reg
atlas_scripts_SCRIPTS += \
			probe/reg_servers.sh.prod
endif

if INSTALL_MODE_anchor
atlas_data_DATA += \
			anchor/known_hosts.reg
atlas_scripts_SCRIPTS += \
			anchor/reg_servers.sh.prod
endif

BUILT_SOURCES = \
	      common/tmpfiles.conf \
	      common/ripe-atlas.service \
	      $(top_srcdir)/probe-busybox/include/atlas_path.h

CLEANFILES = \
             common/FIRMWARE_APPS_VERSION \
             common/measurement.conf \
             common/tmpfiles.conf \
	     common/ripe-atlas.service \
             $(top_srcdir)/probe-busybox/include/atlas_path.h

common/FIRMWARE_APPS_VERSION:	common/FIRMWARE_APPS_VERSION.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

#
# This is a hack to ensure that atlas_path.h gets created prior
# to probe-busybox being built.
# all-local:      $(top_srcdir)/probe-busybox/include/atlas_path.h


