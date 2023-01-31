AC_PREREQ([2.68])
AC_INIT([ripe-atlas], [m4_esyscmd_s([cat VERSION])], [gmeyer@ripe.net])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign])

# system paths
storage_sysconfdir=/storage/etc
tmpdir=/tmp

# application dependent paths
rpm_base_dir=/usr/local/ripe-atlas
working_dir=/home/atlas

# runtime info
ripe_atlas_user=ripe-atlas

AC_SUBST(storage_sysconfdir)
AC_SUBST(tmpdir)
AC_SUBST(rpm_base_dir)
AC_SUBST(working_dir)
AC_SUBST(ripe_atlas_user)

AC_PROG_LIBTOOL
AC_PROG_CC

AC_CONFIG_FILES([
Makefile
bin/ATLAS
bin/common-pre.sh
bin/common.sh
bin/reginit.sh
bin/resolvconf
bin/arch/generic/generic-ATLAS.sh
bin/arch/generic/generic-common.sh
bin/arch/generic/generic-reginit.sh
bin/ripe-atlas.service
atlas-config/state/FIRMWARE_APPS_VERSION
])

AC_CONFIG_SUBDIRS([probe-busybox/libevent-2.1.11-stable])
AC_OUTPUT
