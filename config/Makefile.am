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
		    common/ripe-atlas.run.conf

CLEANFILES += \
             common/ripe-atlas.run.conf \
	     common/ripe-atlas.service

if SINGLE_USER
systemd_sysusers_DATA = \
		    common/ripe-atlas.user.conf

CLEANFILES += \
	     common/ripe-atlas.user.conf
else
systemd_sysusers_DATA = \
		    common/ripe-atlas.users.conf

CLEANFILES += \
	     common/ripe-atlas.users.conf
endif

endif

atlas_sysconf_DATA = \
			common/mode

#
# This is a hack to ensure that atlas_path.h gets created prior
# to probe-busybox being built.
BUILT_SOURCES = \
	      $(top_srcdir)/probe-busybox/include/atlas_path.h

common/FIRMWARE_APPS_VERSION:	common/FIRMWARE_APPS_VERSION.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

if SYSTEMD_INSTALL
install-data-hook:
if SINGLE_USER
	@mv -f $(DESTDIR)$(systemd_sysusersdir)/ripe-atlas.user.conf \
	       $(DESTDIR)$(systemd_sysusersdir)/ripe-atlas.conf
else
	@mv -f $(DESTDIR)$(systemd_sysusersdir)/ripe-atlas.users.conf \
	       $(DESTDIR)$(systemd_sysusersdir)/ripe-atlas.conf
endif
	@mv -f $(DESTDIR)$(systemd_tmpfilesdir)/ripe-atlas.run.conf \
	       $(DESTDIR)$(systemd_tmpfilesdir)/ripe-atlas.conf
endif
if DO_CHOWN
	chown $(ripe_atlas_user):$(ripe_atlas_group) $(DESTDIR)/$(atlas_sysconfdir)/mode
endif
