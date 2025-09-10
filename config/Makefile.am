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

# FreeBSD rc.d service script
CLEANFILES += \
	     freebsd/ripe-atlas.rc.d

atlas_sysconf_DATA = \
			common/mode

if PROBE_TYPE_V3
atlas_data_DATA += \
			probe/2017-11-07-dev.pem \
			probe/2017-11-07-prod.pem \
			probe/2017-11-07-test.pem
else
if PROBE_TYPE_V4
atlas_data_DATA += \
			probe/2018-04-23-dev.pem \
			probe/2018-04-23-prod.pem \
			probe/2018-04-23-test.pem
else
if PROBE_TYPE_V5
atlas_data_DATA += \
			probe/2021-02-02-dev.pem \
			probe/2021-02-02-prod.pem \
			probe/2021-02-02-test.pem
endif # PROBE_TYPE_V5

endif # PROBE_TYPE_V4

endif # PROBE_TYPE_V3

#
# This is a hack to ensure that atlas_path.h gets created prior
# to probe-busybox being built.
BUILT_SOURCES = \
	      $(top_srcdir)/probe-busybox/include/atlas_path.h

common/FIRMWARE_APPS_VERSION:	common/FIRMWARE_APPS_VERSION.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

install-data-hook:
if SYSTEMD_INSTALL
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

# Install FreeBSD rc.d service script
	@if [ "$(probe_type)" = "freebsd" ]; then \
		echo "Installing FreeBSD rc.d service script"; \
		mkdir -p $(DESTDIR)/usr/local/etc/rc.d; \
		cp config/freebsd/ripe-atlas.rc.d $(DESTDIR)/usr/local/etc/rc.d/ripe-atlas; \
		chmod 755 $(DESTDIR)/usr/local/etc/rc.d/ripe-atlas; \
		echo "FreeBSD service script installed to /usr/local/etc/rc.d/ripe-atlas"; \
		echo "To enable the service, add to /etc/rc.conf:"; \
		echo "  echo 'ripe_atlas_enable=\"YES\"' >> /etc/rc.conf"; \
		echo "Then start with: service ripe-atlas start"; \
	fi
