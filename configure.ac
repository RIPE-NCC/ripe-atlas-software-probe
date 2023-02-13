AC_PREREQ([2.68])
AC_INIT([ripe-atlas], [m4_esyscmd_s([cat VERSION])], [gmeyer@ripe.net])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign])

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
atlas_libexecdir=${libexecdir}/ripe-atlas
atlas_datadir=${datadir}/ripe-atlas
atlas_sysconfdir=${sysconfdir}/ripe-atlas
atlas_spooldir=${localstatedir}/spool/ripe-atlas
atlas_rundir=${localstatedir}/run/ripe-atlas

storage_sysconfdir=/storage/etc
tmpdir=/tmp

# application dependent paths
rpm_base_dir=/usr/local/ripe-atlas
working_dir=/home/ripe-atlas

# runtime info
ripe_atlas_user=ripe-atlas
ripe_atlas_group=ripe-atlas

AC_SUBST(storage_sysconfdir)
AC_SUBST(tmpdir)
AC_SUBST(rpm_base_dir)
AC_SUBST(working_dir)
AC_SUBST(ripe_atlas_user)
AC_SUBST(ripe_atlas_group)

AC_SUBST(atlas_libexecdir)
AC_SUBST(atlas_datadir)
AC_SUBST(atlas_sysconfdir)
AC_SUBST(atlas_spooldir)
AC_SUBST(atlas_rundir)

AC_PROG_LIBTOOL
AC_PROG_CC

AC_CONFIG_FILES([
Makefile
bin/ATLAS
bin/common-pre.sh
bin/common.sh
bin/reginit.sh
bin/resolvconf
bin/config.sh
bin/arch/generic/generic-ATLAS.sh
bin/arch/generic/generic-common.sh
bin/arch/generic/generic-reginit.sh
bin/ripe-atlas.service
atlas-config/state/FIRMWARE_APPS_VERSION
])

AC_CONFIG_SUBDIRS([probe-busybox/libevent-2.1.11-stable])
AC_OUTPUT
