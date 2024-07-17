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
             -e 's|@probe_scripts_path[@]|$(probe_scripts_path)|g' \
             -e 's|@ripe_atlas_user[@]|$(ripe_atlas_user)|g' \
             -e 's|@ripe_atlas_measurement[@]|$(ripe_atlas_measurement)|g' \
             -e 's|@ripe_atlas_group[@]|$(ripe_atlas_group)|g' \
             -e 's|@sbindir[@]|$(sbindir)|g' \
	     -e 's|@sharedstatedir[@]|$(sharedstatedir)|g' \
             -e 's|@storage_sysconfdir[@]|$(storage_sysconfdir)|g' \
             -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
             -e 's|@tmpdir[@]|$(tmpdir)|g' \
             -e 's|@VERSION[@]|$(VERSION)|g'

%.service:	%.service.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

%.conf:	%.conf.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

%.h:	%.h.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@

%.sh:	%.sh.in
	@rm -f $@
	$(AM_V_GEN)$(SUBST_PATHS) $< > $@
