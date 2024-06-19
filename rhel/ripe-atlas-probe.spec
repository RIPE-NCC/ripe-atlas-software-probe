%define     git_repo         ripe-atlas-software-probe
%define     build_dirname    %{git_repo}
%define     base_path        ripe-atlas
%define     service_name     ripe-atlas.service
%define     version          %(find . -name VERSION | head -1 | xargs -I {} sh -c "cat {}")

# define user to perform measurements
%define     atlas_measurement  ripe-atlas-measurement
%define     atlas_user         ripe-atlas
%define     atlas_group        ripe-atlas

# flag to ignore files installed in builddir but not packaged in the final RPM
%define	    _unpackaged_files_terminate_build	0

# prevent creation of the build ids in /usr/lib -> see https://access.redhat.com/discussions/5045161
%define	    _build_id_links none

# Files to migrate
%define	    atlas_olddir       /var/atlas-probe
%define	    atlas_oldkey       %{atlas_olddir}/etc/probe_key
%define	    atlas_oldmode      %{atlas_olddir}/state/mode
%define	    atlas_oldconfig    %{atlas_olddir}/state/config.txt
%define	    atlas_newdir       %{_sysconfdir}/%{base_path}
%define	    atlas_newkey       %{atlas_newdir}/probe_key
%define	    atlas_newmode      %{atlas_newdir}/mode
%define	    atlas_newconfig    %{atlas_newdir}/config.txt

# Workaround for systems using autoconf 2.69 and older
%if 0%{?rhel} >= 9
%define	    fix_rundir         %{_rundir}
%else
%define	    fix_rundir         %{_localstatedir}/run
%endif

%define     rpm_statedir       %{_localstatedir}/lib/rpm-state/%{base_path}

# Keep scripts intact
%define     __brp_mangle_shebangs_exclude_from ^%{_libexecdir}/%{base_path}/scripts/.*$

Name:	    	ripe-atlas-common
Summary:    	RIPE Atlas Software Probe Essentials
Group:      	Applications/Internet
Version:    	%{version}
Release:    	1%{?dist}
License:    	GPLv3.0
Requires:   	%{?el6:daemontools} %{?el7:psmisc} %{?el8:psmisc} openssh-clients iproute %{?el7:sysvinit-tools} %{?el8:procps-ng} net-tools hostname /bin/sh bash
Requires(pre):  %{_sbindir}/semanage %{_bindir}/systemd-sysusers %{_bindir}/systemd-tmpfiles
Requires(post): %{_sbindir}/semanage
BuildRequires:	rpm systemd-rpm-macros %{?el7:systemd} %{?el8:systemd} openssl-devel autoconf automake libtool make
URL:            https://atlas.ripe.net/
%{systemd_requires}

%description
Essential core assets used in all probe flavours. This package must be installed for a probe to operate as expected.

%package -n ripe-atlas-probe
Summary:	RIPE Atlas Software Probe
Group:		Applications/Internet
BuildArch:      noarch 
Requires:	ripe-atlas-common = %{version}-%{release}
Provides:	ripe-atlas-software-probe
Obsoletes:	atlasswprobe < 5080-3%{?dist}
Conflicts:      atlasprobe, atlasswprobe, ripe-atlas-anchor
URL:            https://atlas.ripe.net/apply/swprobe/

%description -n ripe-atlas-probe
Probe specific files and configurations that form a working software probe. Please visit https://atlas.ripe.net/apply/swprobe/ to register.

%prep
echo "Building for probe version: %{version}"

# performing the steps of '%setup' manually since we are pulling from a remote git repo
echo "Cleaning build dir"
cd %{_builddir}
rm -rf %{_builddir}/%{build_dirname}
echo "Getting Sources..."

%{!?git_tag:%define git_tag master}
%{!?git_source:%define git_source https://github.com/RIPE_NCC}

git clone -b %{git_tag} --recursive %{git_source}/%{git_repo}.git %{_builddir}/%{build_dirname}

cd %{_builddir}/%{build_dirname}
%{?git_commit:git checkout %{git_commit}}

%build
cd %{_builddir}/%{build_dirname}
autoreconf -iv
./configure \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir} \
	--localstatedir=%{_localstatedir} \
	--libdir=%{_libdir} \
%if 0%{?rhel} >= 9
	--runstatedir=%{fix_rundir} \
%endif
	--with-user=%{atlas_user} \
	--with-group=%{atlas_group} \
	--with-measurement-user=%{atlas_measurement} \
	--enable-systemd \
	--disable-chown \
	--disable-setcap-install \
	--with-install-mode=probe
make

%install
cd %{_builddir}/%{build_dirname}
make DESTDIR=%{buildroot} install

%files
%{_sbindir}/*
%dir %{_datadir}/%{base_path}
%{_unitdir}/%{service_name}
%{_sysusersdir}/ripe-atlas.conf
%{_tmpfilesdir}/ripe-atlas.conf
%attr(0644, root, root) %{_datadir}/%{base_path}/measurement.conf
%{_datadir}/%{base_path}/FIRMWARE_APPS_VERSION
%config(noreplace) %attr(0644, %{atlas_user}, %{atlas_group}) %{atlas_newmode}
%attr(0770, %{atlas_user}, %{atlas_group}) %dir %{_sysconfdir}/%{base_path}
%dir %{_libexecdir}/%{base_path}
%dir %{_libexecdir}/%{base_path}/measurement/
%{_libexecdir}/%{base_path}/measurement/a*
%{_libexecdir}/%{base_path}/measurement/buddyinfo
%{_libexecdir}/%{base_path}/measurement/c*
%{_libexecdir}/%{base_path}/measurement/d*
%{_libexecdir}/%{base_path}/measurement/e*
%{_libexecdir}/%{base_path}/measurement/h*
%{_libexecdir}/%{base_path}/measurement/o*
%{_libexecdir}/%{base_path}/measurement/p*
%{_libexecdir}/%{base_path}/measurement/r*
%{_libexecdir}/%{base_path}/measurement/t*
%caps(cap_net_raw=ep) %attr(4750, %{atlas_measurement}, %{atlas_group}) %{_libexecdir}/%{base_path}/measurement/busybox
%dir %{_libexecdir}/%{base_path}/scripts
%exclude %{_libexecdir}/%{base_path}/scripts/reg_servers.sh.*
%{_libexecdir}/%{base_path}/scripts/resolvconf
%{_libexecdir}/%{base_path}/scripts/*.sh
%ghost %{fix_rundir}/%{base_path}

%files -n ripe-atlas-probe
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.*
%ghost %{_sysconfdir}/%{base_path}/reg_servers.sh


%define get_state() [ -f "%{rpm_statedir}/%1" ]

%define init_state() \
mkdir -p %{rpm_statedir} \
systemctl "%1" --quiet %{service_name} 1>/dev/null 2>&1 \
if [ $? -eq 0 ]; then \
	touch "%{rpm_statedir}/%1" 2>/dev/null \
else \
	rm -f "%{rpm_statedir}/%1" 2>/dev/null \
fi \
%{nil}

%define clear_state() rm -rf %{rpm_statedir} 1>/dev/null 2>&1

%pre -n ripe-atlas-common
%init_state is-active
%init_state is-enabled
systemctl stop %{service_name} 1>/dev/null 2>&1
systemctl disable %{service_name} 1>/dev/null 2>&1
%{_bindir}/systemd-sysusers --replace=%{_sysusersdir}/ripe-atlas.conf - <<EOF
g %{atlas_group} -
u %{atlas_user} - "RIPE Atlas" %{fix_rundir}/%{base_path} -
m %{atlas_user} %{atlas_group}
u %{atlas_measurement} - "RIPE Atlas Measurements" %{_localstatedir}/spool/%{base_path} -
m %{atlas_measurement} %{atlas_group}
EOF

%{_sbindir}/semanage fcontext -a -f a -t bin_t -r s0 %{_sbindir}/ripe-atlas 1>/dev/null 2>&1 || :
exit 0

%post -n ripe-atlas-common
%{_bindir}/systemd-tmpfiles --create %{_tmpfilesdir}/ripe-atlas.conf

chmod 0770 "%{atlas_newdir}" 1>/dev/null 2>&1 || :
chown "%{atlas_user}:%{atlas_group}" "%{atlas_newdir}" 1>/dev/null 2>&1 || :

if [ $1 -eq 0 ]; then
	%{_sbindir}/semanage fcontext -d -f a -t bin_t -r s0 %{_sbindir}/ripe-atlas > /dev/null 2>&1 || :
fi
exit 0

%define migrate_file() \
if ( [ -f "%1" ] && ! cmp -s "%1" "%2" 1>/dev/null 2>&1 ); then \
	install -D -p -m "%3" -o "%4" -g "%5" "%1" "%2" 1>/dev/null 2>&1; \
fi \
%{nil}

%post -n ripe-atlas-probe
# Migrate configuration files
%migrate_file %{atlas_oldkey}     %{atlas_newkey}     0600 %{atlas_user} %{atlas_group}
%migrate_file %{atlas_oldkey}.pub %{atlas_newkey}.pub 0644 %{atlas_user} %{atlas_group}
%migrate_file %{atlas_oldmode}    %{atlas_newmode}    0644 %{atlas_user} %{atlas_group}
%migrate_file %{atlas_oldconfig}  %{atlas_newconfig}  0644 %{atlas_user} %{atlas_group}

# clean up old atlas installation, it is now obsolete
if ( [ -f "%{atlas_newkey}" ] &&
     [ -f "%{atlas_newkey}.pub" ] &&
     [ -f "%{atlas_newmode}" ] &&
     [ -d "%{atlas_olddir}" ] ); then
	# NOTE: %{atlas_newconfig} may not exist
	# if %{atlas_oldconfig} did not either
	rm -rf "%{atlas_olddir}"
fi

# clean environment of previous version (if any)
# on upgrade systemd restarts after this
rm -fr %{fix_rundir}/%{base_path}/status/* %{_sysconfdir}/%{base_path}/reg_servers.sh

%systemd_post %{service_name}

if %{get_state is-active}; then
	systemctl start %{service_name} 1>/dev/null 2>&1
fi

if %{get_state is-enabled}; then
	systemctl enable %{service_name} 1>/dev/null 2>&1
fi

%clear_state
exit 0

%preun -n ripe-atlas-probe
exit 0

%preun -n ripe-atlas-common
# Uninstall
if [ $1 -eq 0 ]; then
	systemctl stop %{service_name} 1>/dev/null 2>&1
	systemctl disable %{service_name} 1>/dev/null 2>&1
	# clean environment; %files doesn't support leaving directories but removing files
	rm -f %{fix_rundir}/%{base_path}/pids/* \
	      %{fix_rundir}/%{base_path}/status/* \
	      %{_localstatedir}/spool/%{base_path}/crons/* \
	      %{_localstatedir}/spool/%{base_path}/crons/*/* \
	      %{_localstatedir}/spool/%{base_path}/data/*/* \
	      1>/dev/null 2>&1
fi
exit 0

%postun -n ripe-atlas-common
exit 0

%postun -n ripe-atlas-probe
exit 0

%include rhel/changelog
