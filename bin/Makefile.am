include $(top_srcdir)/rules.mk

sbin_SCRIPTS = \
               ripe-atlas

atlas_scripts_SCRIPTS = \
                        arch/$(probe_scripts_path)/$(probe_scripts_path)-ATLAS.sh \
                        arch/$(probe_scripts_path)/$(probe_scripts_path)-common.sh \
                        arch/$(probe_scripts_path)/$(probe_scripts_path)-reginit.sh \
                        arch/linux/linux-functions.sh \
                        array.lib.sh \
                        atlas_log.lib.sh \
                        class.lib.sh \
                        json.lib.sh \
                        paths.lib.sh \
                        support.lib.sh \
                        common.sh \
                        common-pre.sh \
                        config.sh \
                        reginit.sh \
                        resolvconf

CLEANFILES = \
             paths.lib.sh \
             common.sh \
             common-pre.sh \
             config.sh \
             reginit.sh \
             ripe-atlas \
             resolvconf

ripe-atlas:	ripe-atlas.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

resolvconf:	resolvconf.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@
