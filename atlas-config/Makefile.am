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

CLEANFILES = \
             common/FIRMWARE_APPS_VERSION \
             common/measurement.conf \
             $(top_srcdir)/probe-busybox/include/atlas_path.h

if SYSTEMD_INSTALL
systemd_units_DATA = \
		    common/ripe-atlas.service
systemd_tmpfiles_DATA = \
		    common/ripe-atlas.conf
CLEANFILES += \
             common/ripe-atlas.conf \
	     common/ripe-atlas.service
endif

#
# This is a hack to ensure that atlas_path.h gets created prior
# to probe-busybox being built.
BUILT_SOURCES = \
	      $(top_srcdir)/probe-busybox/include/atlas_path.h

common/FIRMWARE_APPS_VERSION:	common/FIRMWARE_APPS_VERSION.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@
