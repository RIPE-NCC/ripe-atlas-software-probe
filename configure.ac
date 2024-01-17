AC_PREREQ([2.68])
AC_INIT([ripe-atlas], [m4_esyscmd_s([cat VERSION])], [mstam@ripe.net])

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

probe_type=${with_probe_type}
AC_SUBST(probe_type)

AS_CASE([$probe_type],
	[*openwrt*], [probe_scripts_path=$probe_type],
	[probe_scripts_path=generic])
AC_SUBST(probe_scripts_path)
AM_CONDITIONAL([PROBE_TYPE_V3], [test "x${probe_type}" = 'xopenwrt-atlas-probev3'])
AM_CONDITIONAL([PROBE_TYPE_V4], [test "x${probe_type}" = 'xopenwrt-atlas-probev4'])
AM_CONDITIONAL([PROBE_TYPE_V5], [test "x${probe_type}" = 'xopenwrt-atlas-probev5'])

AC_ARG_ENABLE([chown],
	      [AS_HELP_STRING([--enable-chown], [set permissions during install @<:@default=yes@:>@])],
	      [case "${enableval}" in
			yes) do_chown=true ;;
			no) do_chown=false ;;
		     *) AC_MSG_ERROR([bad value ${enableval} for --enable-chown]) ;;
	     esac],[do_chown=true])
AM_CONDITIONAL([DO_CHOWN], [test "x${do_chown}" = 'xtrue'])
if test "x${do_chown}" != 'xtrue'; then
	AC_MSG_WARN([Disabling chown may prevent the probe from running as a non-privileged user])
fi

ripe_atlas_user=
ripe_atlas_group=
ripe_atlas_measurement=
AC_ARG_WITH([user], [AS_HELP_STRING([--with-user], [run main process as username @<:@default=ripe-atlas@:>@])], [ripe_atlas_user="${withval}"], [])
AC_ARG_WITH([measurement-user], [AS_HELP_STRING([--with-measurement-user], [run measurement processes as username @<:@default=--with-user@:>@])], [ripe_atlas_measurement="${withval}"], [])
AC_ARG_WITH([group], [AS_HELP_STRING([--with-group], [run group @<:@default=ripe-atlas@:>@])], [ripe_atlas_group="${withval}"], [])

if test -z "${ripe_atlas_user}"; then
	ripe_atlas_user='ripe-atlas'
fi

if ! grep -qE "^${ripe_atlas_user}:" /etc/passwd; then
	AC_MSG_WARN([User ${ripe_atlas_user} doesn't seem to exist, installation may fail])
fi

if test -z "${ripe_atlas_group}"; then
	ripe_atlas_group='ripe-atlas'
fi

if ! grep -qE "^${ripe_atlas_group}:" /etc/group; then
	AC_MSG_WARN([Group ${ripe_atlas_group} doesn't seem to exist, installation may fail])
fi

if test -z "${ripe_atlas_measurement}"; then
	ripe_atlas_measurement="${ripe_atlas_user}"
fi

if ! grep -qE "^${ripe_atlas_measurement}:" /etc/passwd; then
	AC_MSG_WARN([User ${ripe_atlas_measurement} doesn't seem to exist, installation may fail])
fi
AM_CONDITIONAL(SINGLE_USER, [test "${ripe_atlas_measurement}" = "${ripe_atlas_user}"])

AC_SUBST(ripe_atlas_user)
AC_SUBST(ripe_atlas_group)
AC_SUBST(ripe_atlas_measurement)

# use the following arguments for the '--with-install-mode' flag
# common: common, non-probe specific
# probe: (software) probe
# anchor
AC_ARG_WITH([install-mode], [AS_HELP_STRING([--with-install-mode], [define the purpose of the probe (probe,anchor,common)])], [], [with_install_mode=probe])

AM_CONDITIONAL([INSTALL_MODE_probe], [test "x${with_install_mode}" = 'xprobe'])
AM_CONDITIONAL([INSTALL_MODE_anchor], [test "x${with_install_mode}" = 'xanchor'])

AC_PATH_PROG(SETCAP, setcap)
AC_ARG_ENABLE([setcap-install], [AC_HELP_STRING([--enable-setcap-install], [install measurements with cap_net_raw @<:@default=yes@:>@])], [enable_setcap_install="${enableval}"],[enable_setcap_install=yes])

AC_MSG_CHECKING([whether to install measurements with cap_net_raw capabilities])
if test "x${enable_setcap_install}" = 'xno'; then
	AC_MSG_RESULT([no])
	AC_MSG_WARN([Disabling setcap installation may prevent the probe from running as a non-privileged user])
else
	if test "x${SETCAP}" = 'x'; then
		AC_MSG_RESULT([no. 'setcap' not found])
	else
		AC_MSG_RESULT([yes])
	fi
fi

AM_CONDITIONAL(SETCAP_INSTALL, [test "x${enable_setcap_install}" = 'xyes'])

AC_PATH_PROG(SYSTEMDPATH, systemd-path)
AC_ARG_ENABLE([systemd], [AC_HELP_STRING([--enable-systemd], [install files for systemd @<:@default=yes@:>@])], [enable_systemd="${enableval}"],[enable_systemd=yes])

AC_MSG_CHECKING([whether to install systemd support files])
systemd_tmpfilesdir=
systemd_unitsdir=
systemd_sysusersdir=
if test "x${enable_systemd}" = 'xno'; then
	AC_MSG_RESULT([no])
else
	if test "x${SYSTEMDPATH}" != 'x'; then
		AC_MSG_RESULT([yes])
		systemd_tmpfilesdir=$(${SYSTEMDPATH} tmpfiles)
		systemd_unitsdir=$(${SYSTEMDPATH} systemd-system-unit)
		systemd_sysusersdir=$(${SYSTEMDPATH} sysusers)
	else
		AC_MSG_RESULT([no. 'systemd-path' not found])
	fi
fi
AM_CONDITIONAL(SYSTEMD_INSTALL, [test "x${SYSTEMDPATH}" != 'x' -a "x${enable_systemd}" = 'xyes'])
AC_SUBST(systemd_tmpfilesdir)
AC_SUBST(systemd_unitsdir)
AC_SUBST(systemd_sysusersdir)

# system paths
atlas_libexecdir="${libexecdir}/ripe-atlas"
atlas_datadir="${datadir}/ripe-atlas"
atlas_measurementdir="${atlas_libexecdir}/measurement"
if [ -n "${runstatedir}" ]; then
	atlas_rundir="${runstatedir}/ripe-atlas"
else
	atlas_rundir="${localstatedir}/run/ripe-atlas"
fi
atlas_scriptsdir="${atlas_libexecdir}/scripts"
atlas_spooldir="${localstatedir}/spool/ripe-atlas"
atlas_sysconfdir="${sysconfdir}/ripe-atlas"

storage_sysconfdir=/storage/etc
tmpdir=/tmp

AC_SUBST(storage_sysconfdir)
AC_SUBST(tmpdir)

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
config/Makefile
bin/Makefile
])

AC_CONFIG_SUBDIRS([probe-busybox/libevent-2.1.11-stable])
AC_OUTPUT
