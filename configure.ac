AC_PREREQ([2.68])
AC_INIT([ripe-atlas], [m4_esyscmd_s([cat VERSION])], [gmeyer@ripe.net])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

# use the following arguments for '--with-probe-type' flag
# v3: openwrt-atlas-probev3
# v4: openwrt-atlas-probev4
# v5: openwrt-atlas-probev5
# centos: centos-rpm-<PACKAGE_NAME>-<PACKAGE_VERSION>-<PACKAGE_RELEASE>  (ie. centos-rpm-ripe-atlas-probe-5090-1.el7)
# debian: debian-<PACKAGE_NAME>-<VERSION>  (ie. debian-ripe-atlas-probe-5090)
AC_ARG_WITH([probe-type], [AS_HELP_STRING([--with-probe-type], [define which probe flavour should be built (v3,v4,v5)])], [], [with_probe_type=no])

probe_type=$with_probe_type
AC_SUBST(probe_type)

AS_CASE([$probe_type],
	[*openwrt*], [probe_scripts_path=$probe_type],
	[probe_scripts_path=generic])
AC_SUBST(probe_scripts_path)

# system paths
atlas_libexecdir="${libexecdir}/ripe-atlas"
atlas_datadir="${datadir}/ripe-atlas"
atlas_measurementdir="${atlas_libexecdir}/measurement"
atlas_rundir="${localstatedir}/run/ripe-atlas"
atlas_scriptsdir="${atlas_libexecdir}/scripts"
atlas_spooldir="${localstatedir}/spool/ripe-atlas"
atlas_sysconfdir="${sysconfdir}/ripe-atlas"

storage_sysconfdir=/storage/etc
tmpdir=/tmp

# runtime info
ripe_atlas_user=ripe-atlas
ripe_atlas_group=ripe-atlas

AC_SUBST(storage_sysconfdir)
AC_SUBST(tmpdir)
AC_SUBST(ripe_atlas_user)
AC_SUBST(ripe_atlas_group)

AC_SUBST(atlas_libexecdir)
AC_SUBST(atlas_datadir)
AC_SUBST(atlas_measurementdir)
AC_SUBST(atlas_rundir)
AC_SUBST(atlas_scriptsdir)
AC_SUBST(atlas_sysconfdir)
AC_SUBST(atlas_spooldir)

AC_PROG_LIBTOOL
AC_PROG_CC

AC_CONFIG_FILES([
Makefile
])

AC_CONFIG_SUBDIRS([probe-busybox/libevent-2.1.11-stable])
AC_OUTPUT
