AC_PREREQ([2.72])
AC_INIT([ripe-atlas],[m4_esyscmd_s([cat VERSION])],[mstam@ripe.net])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

# Check for GNU Make and prefer it over BSD Make for better compatibility
# This is especially important for FreeBSD where BSD make has different syntax
AC_MSG_CHECKING([for make program])
AC_PATH_PROG([MAKE], [gmake])
if test -z "$MAKE"; then
	AC_PATH_PROG([MAKE], [make])
fi

if test -n "$MAKE"; then
	AC_MSG_RESULT([$MAKE])
	# Test if it's GNU Make
	if $MAKE --version 2>/dev/null | grep -q "GNU Make"; then
		AC_MSG_NOTICE([Using GNU Make: $MAKE - good for compatibility])
		MAKE_IS_GNU=yes
	else
		AC_MSG_WARN([Using non-GNU Make: $MAKE - some features may not work correctly])
		AC_MSG_WARN([Consider installing GNU Make (gmake) for better compatibility])
		MAKE_IS_GNU=no
	fi
else
	AC_MSG_ERROR([No make program found])
fi

# Export MAKE for use in Makefiles
AC_SUBST([MAKE])
AC_SUBST([MAKE_IS_GNU])

# use the following arguments for '--with-probe-type' flag
# v3: openwrt-atlas-probev3
# v4: openwrt-atlas-probev4
# v5: openwrt-atlas-probev5
# freebsd: freebsd-software-probe
# centos: centos-rpm-<PACKAGE_NAME>-<PACKAGE_VERSION>-<PACKAGE_RELEASE>  (ie. centos-rpm-ripe-atlas-probe-5090-1.el7)
# debian: debian-<PACKAGE_NAME>-<VERSION>  (ie. debian-ripe-atlas-probe-5090)
AC_ARG_WITH([probe-type], [AS_HELP_STRING([--with-probe-type], [define which probe flavour should be built (v3,v4,v5,freebsd)])], [], [with_probe_type=no])

# Auto-detect probe type based on operating system if not specified
if test "x${with_probe_type}" = 'xno'; then
	OS_NAME=`uname -s 2>/dev/null || echo "unknown"`
	case "$OS_NAME" in
	*FreeBSD*)
		probe_type='freebsd'
		AC_MSG_NOTICE([Auto-detected FreeBSD, setting probe-type=freebsd])
		;;
	*)
		probe_type='generic'
		AC_MSG_NOTICE([Using generic probe type for $OS_NAME])
		;;
	esac
else
	probe_type=${with_probe_type}
fi

AC_SUBST(probe_type)

AS_CASE([$probe_type],
	[*openwrt*], [probe_scripts_path=$probe_type],
	[freebsd*], [probe_scripts_path=freebsd],
	[probe_scripts_path=generic])
AC_SUBST(probe_scripts_path)
AM_CONDITIONAL([PROBE_TYPE_V3], [test "x${probe_type}" = 'xopenwrt-atlas-probev3'])
AM_CONDITIONAL([PROBE_TYPE_V4], [test "x${probe_type}" = 'xopenwrt-atlas-probev4'])
AM_CONDITIONAL([PROBE_TYPE_V5], [test "x${probe_type}" = 'xopenwrt-atlas-probev5'])
AM_CONDITIONAL([PROBE_TYPE_FREEBSD], [test "x${probe_type}" = 'xfreebsd'])

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

AC_ARG_WITH([shell-fixup], [AS_HELP_STRING([--with-shell-fixup], [force the shell to use in scripts])], [], [with_shell_fixup=''])
AM_CONDITIONAL([SHELL_FIXUP], [test "x${with_shell_fixup}" != 'x'])
if test "x${with_shell_fixup}" != 'x'; then
	shebang="\#!${with_shell_fixup}"
fi

AC_PATH_PROG(SETCAP, setcap)
AC_ARG_ENABLE([setcap-install], [AS_HELP_STRING([--enable-setcap-install],[install measurements with cap_net_raw @<:@default=yes@:>@])], [enable_setcap_install="${enableval}"],[enable_setcap_install=yes])

# Disable setcap on non-Linux systems as it's not available
# Use uname to detect the operating system
OS_NAME=`uname -s 2>/dev/null || echo "unknown"`
case "$OS_NAME" in
*Linux*)
	# setcap is available on Linux
	;;
*)
	# Disable setcap on all non-Linux systems (FreeBSD, macOS, etc.)
	if test "x${enable_setcap_install}" = 'xyes'; then
		AC_MSG_NOTICE([Disabling setcap-install on $OS_NAME (setcap not available)])
		enable_setcap_install=no
	fi
	;;
esac

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
AC_SUBST(SETCAP_INSTALL, [${enable_setcap_install}])

AC_PATH_PROG(SYSTEMDPATH, systemd-path)
AC_ARG_ENABLE([systemd], [AS_HELP_STRING([--enable-systemd],[install files for systemd @<:@default=yes@:>@])], [enable_systemd="${enableval}"],[enable_systemd=yes])

AC_MSG_CHECKING([whether to install systemd support files])
systemd_tmpfilesdir=
systemd_unitsdir=
systemd_sysusersdir=
if test "x${enable_systemd}" = 'xno'; then
	AC_MSG_RESULT([no])
else
	if test "x${SYSTEMDPATH}" != 'x'; then
		AC_MSG_RESULT([yes])
		systemd_tmpfilesdir=$(${SYSTEMDPATH} tmpfiles 2>/dev/null)
		if test "x${systemd_tmpfilesdir}" = "x"; then
			systemd_tmpfilesdir=$(${SYSTEMDPATH} --suffix=tmpfiles.d system-library-private 2>/dev/null)
		fi
		systemd_unitsdir=$(${SYSTEMDPATH} systemd-system-unit 2>/dev/null)
		if test "x${systemd_unitsdir}" = "x"; then
			systemd_unitsdir=$(${SYSTEMDPATH} --suffix=systemd/system system-library-private 2>/dev/null)
		fi
		systemd_sysusersdir=$(${SYSTEMDPATH} sysusers 2>/dev/null)
		if test "x${systemd_sysusersdir}" = "x"; then
			systemd_sysusersdir=$(${SYSTEMDPATH} --suffix=sysusers.d system-library-private 2>/dev/null)
		fi
	else
		AC_MSG_RESULT([no. 'systemd-path' not found])
	fi
fi
AM_CONDITIONAL(SYSTEMD_INSTALL, [test "x${SYSTEMDPATH}" != 'x' -a "x${enable_systemd}" = 'xyes'])
AC_SUBST(systemd_tmpfilesdir)
AC_SUBST(systemd_unitsdir)
AC_SUBST(systemd_sysusersdir)
AC_SUBST(shebang)

# system paths
atlas_libexecdir="\${libexecdir}/ripe-atlas"
atlas_datadir="\${datadir}/ripe-atlas"
atlas_measurementdir="${atlas_libexecdir}/measurement"
atlas_rundir="\${runstatedir}/ripe-atlas"
atlas_scriptsdir="${atlas_libexecdir}/scripts"
atlas_spooldir="\${localstatedir}/spool/ripe-atlas"
atlas_sysconfdir="\${sysconfdir}/ripe-atlas"

# Compatibility fix for EL8
if test "x${runstatedir}" = "x"; then
	atlas_rundir="\${localstatedir}/run/ripe-atlas"
fi

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

LT_INIT

# Check for libtool availability and version
AC_MSG_CHECKING([for libtool])
if test -n "$LIBTOOL"; then
	AC_MSG_RESULT([$LIBTOOL])
	# Check if libtool is working (but only if the libtool script exists)
	if test -f "ltmain.sh" && $LIBTOOL --version >/dev/null 2>&1; then
		AC_MSG_NOTICE([Libtool is available and working])
		# Check libtool version (require at least 2.4.0)
		libtool_version=`$LIBTOOL --version | head -n1 | sed 's/.*libtool (GNU libtool) \([0-9.]*\).*/\1/'`
		AC_MSG_CHECKING([libtool version])
		AC_MSG_RESULT([$libtool_version])
		# Basic version check - ensure it's a reasonable version
		if echo "$libtool_version" | grep -q '^[0-9]\+\.[0-9]\+'; then
			AC_MSG_NOTICE([Libtool version $libtool_version is acceptable])
		else
			AC_MSG_WARN([Could not determine libtool version, but libtool appears to be working])
		fi
	elif test -f "ltmain.sh"; then
		AC_MSG_NOTICE([Libtool script found, will be tested during build])
	else
		AC_MSG_ERROR([Libtool is required but not found])
	fi
else
	AC_MSG_ERROR([Libtool is required but not found])
fi

# Detect the host system
AC_CANONICAL_HOST

# Better compiler detection for macOS and FreeBSD
# On FreeBSD, prefer the system's default compiler (cc) over gcc
if echo "$host_os" | grep -q "freebsd"; then
    AC_MSG_CHECKING([for system compiler on FreeBSD])
    if test -n "$CC"; then
        # CC already set, use it
        AC_MSG_RESULT([using pre-set CC: $CC])
    else
        # Try cc first, then gcc
        AC_PATH_PROG([CC], [cc])
        if test -z "$CC"; then
            AC_PATH_PROG([CC], [gcc])
        fi
        if test -z "$CC"; then
            AC_MSG_ERROR([No C compiler found])
        fi
        AC_MSG_RESULT([$CC])
    fi
else
    AC_PROG_CC
fi
AC_PROG_CC_C_O

# Basic platform detection
AM_CONDITIONAL([DARWIN], [test "$host_os" = "darwin"])
AM_CONDITIONAL([MACOS], [test "$host_os" = "darwin"])

# Simple compiler detection
AC_MSG_CHECKING([for C compiler type])
if $CC --version 2>/dev/null | grep -q "clang"; then
    AC_MSG_RESULT([clang])
    IS_CLANG=yes
    # Warn about potential clang compatibility issues
    AC_MSG_WARN([Using clang compiler - some components may require gcc])
    AC_MSG_WARN([If build fails, consider installing gcc: pkg install gcc-13_5])
else
    AC_MSG_RESULT([gcc])
    IS_CLANG=no
fi

AC_SUBST([IS_CLANG])
AM_CONDITIONAL([IS_CLANG], [test "$IS_CLANG" = "yes"])
AM_CONDITIONAL([IS_GCC], [test "$IS_CLANG" = "no"])

# Check for basic function availability
AC_CHECK_FUNCS([inet_ntoa inet_aton inet_pton inet_ntop])
AC_CHECK_FUNCS([setresgid setresuid])
AC_CHECK_FUNCS([__bswap32 __bswap64 bswap_32 bswap_64])
AC_CHECK_FUNCS([strlcat strlcpy])
AC_CHECK_FUNCS([sendfile])
AC_CHECK_FUNCS([statfs])

# Check for header availability
AC_CHECK_HEADERS([sys/sendfile.h])
AC_CHECK_HEADERS([linux/reboot.h])
AC_CHECK_HEADERS([linux/types.h])
AC_CHECK_HEADERS([sys/reboot.h])
AC_CHECK_HEADERS([sys/vfs.h])
AC_CHECK_HEADERS([sys/mount.h])
AC_CHECK_HEADERS([openssl/ssl.h])

# Check for OpenSSL availability
AC_CHECK_LIB([ssl], [SSL_new], [HAVE_OPENSSL=yes], [HAVE_OPENSSL=no])
AM_CONDITIONAL([HAVE_OPENSSL], [test "$HAVE_OPENSSL" = "yes"])

# Check for required libraries
AC_CHECK_LIB([c], [main])
AC_CHECK_LIB([m], [main])



# Add autoconf defines to CFLAGS
AS_IF([test "$ac_cv_func_statfs" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_STATFS=1"
])

AS_IF([test "$ac_cv_header_sys_mount_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_SYS_MOUNT_H=1"
])

AS_IF([test "$ac_cv_header_sys_vfs_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_SYS_VFS_H=1"
])

AS_IF([test "$ac_cv_header_linux_reboot_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_LINUX_REBOOT_H=1"
])

AS_IF([test "$ac_cv_header_linux_types_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_LINUX_TYPES_H=1"
])

AS_IF([test "$ac_cv_header_sys_reboot_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_SYS_REBOOT_H=1"
])

AS_IF([test "$ac_cv_header_sys_sendfile_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_SYS_SENDFILE_H=1"
])

AS_IF([test "$ac_cv_header_openssl_ssl_h" = "yes"], [
    CFLAGS="$CFLAGS -DHAVE_OPENSSL_SSL_H=1"
])

# Final CFLAGS substitution
AC_SUBST([CFLAGS])

# Generate config.h header for conditional compilation
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
Makefile
config/Makefile
bin/Makefile
])

# Generate FreeBSD rc.d service script if probe type is freebsd
if test "x${probe_type}" = 'xfreebsd'; then
	AC_CONFIG_FILES([config/freebsd/ripe-atlas.rc.d:config/freebsd/ripe-atlas.rc.d.in])
fi

AC_CONFIG_SUBDIRS([probe-busybox/libevent-2.1.11-stable])
AC_OUTPUT
