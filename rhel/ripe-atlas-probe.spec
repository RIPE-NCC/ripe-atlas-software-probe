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

# transition directory key storage
%define	    atlas_olddir       /var/atlas-probe/etc
%define	    atlas_oldkey       %{atlas_olddir}/probe_key
%define	    atlas_newdir       %{_sysconfdir}/%{base_path}
%define	    atlas_newkey       %{atlas_newdir}/probe_key

# Keep scripts intact
%define     __brp_mangle_shebangs_exclude_from ^%{_libexecdir}/%{base_path}/scripts/.*$

Name:	    	ripe-atlas-common
Summary:    	RIPE Atlas Software Probe Essentials
Group:      	Applications/Internet
Version:    	%{version}
Release:    	1%{?dist}
License:    	RIPE NCC
Requires:   	%{?el6:daemontools} %{?el7:psmisc} %{?el8:psmisc} openssh-clients iproute %{?el7:sysvinit-tools} %{?el8:procps-ng} net-tools hostname
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
Provides:	atlasswprobe = %{version}-%{release}
Obsoletes:	atlasswprobe < 5080-3%{?dist}
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
./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --localstatedir=%{_localstatedir} --libdir=%{_libdir} --runstatedir=%{_rundir} --with-user=%{atlas_user} --with-group=%{atlas_group} --with-measurement-user=%{atlas_measurement} --enable-systemd --disable-chown --disable-setcap-install --with-install-mode=probe
make

%install
cd %{_builddir}/%{build_dirname}
make DESTDIR=%{buildroot} install

%files
%exclude %dir %{_sbindir}
%{_sbindir}/*
%dir %{_datadir}/%{base_path}
%{_unitdir}/%{service_name}
%{_sysusersdir}/ripe-atlas.conf
%{_tmpfilesdir}/ripe-atlas.conf
%{_datadir}/%{base_path}/measurement.conf
%{_datadir}/%{base_path}/FIRMWARE_APPS_VERSION
%config(noreplace) %attr(0644, %{atlas_user}, %{atlas_group}) %{_sysconfdir}/%{base_path}/mode
%ghost %{_sysconfdir}/%{base_path}/probe_key
%ghost %{_sysconfdir}/%{base_path}/probe_key.pub
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
%attr(2775, %{atlas_measurement}, %{atlas_group}) %{_localstatedir}/spool/%{base_path}
%ghost %{_rundir}/%{base_path}

%files -n ripe-atlas-probe
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod
%ghost %{_sysconfdir}/%{base_path}/reg_servers.sh

%pre -n ripe-atlas-common
%sysusers_create_package ripe-atlas %{_builddir}/%{build_dirname}/config/common/ripe-atlas.users.conf
%tmpfiles_create_package ripe-atlas %{_builddir}/%{build_dirname}/config/common/ripe-atlas.run.conf

# check if probe keys need to be backed up
[ ! -f "%{atlas_oldkey}" ] && exit 0
[ $(cmp -s "%{atlas_oldkey}" "%{atlas_newkey}") ] && exit 0

# migrate probe keys
mkdir -p -m 0770 "%{atlas_newdir}"
cp "%{atlas_oldkey}" "%{atlas_newkey}" 1>/dev/null 2>&1
cp "%{atlas_oldkey}.pub" "%{atlas_newkey}.pub" 1>/dev/null 2>&1
chmod 644 "%{atlas_newkey}.pub"
chmod 400 "%{atlas_newkey}"
chown -R "%{atlas_user}:%{atlas_group}" "%{atlas_newdir}"
exit 0

%pre -n ripe-atlas-probe
exit 0

%post -n ripe-atlas-common
%systemd_post %{service_name}

# clean environment of previous version (if any)
# on upgrade systemd restarts after this
rm -f %{_rundir}/%{base_path}/status/* %{_libexecdir}/%{base_path}/scripts/reg_servers.sh
exit 0

%post -n ripe-atlas-probe
%systemd_post %{service_name}
exit 0

%preun -n ripe-atlas-probe
# Uninstall
if [ $1 -eq 0 ]; then
	systemctl stop %{service_name} 1>/dev/null 2>&1
	systemctl disable %{service_name} 1>/dev/null 2>&1
fi
exit 0

%preun -n ripe-atlas-common
# Uninstall
if [ $1 -eq 0 ]; then
	systemctl stop %{service_name} 1>/dev/null 2>&1
	systemctl disable %{service_name} 1>/dev/null 2>&1

	# clean environment; %files doesn't support leaving directories but removing files
	rm -f %{_rundir}/%{base_path}/pids/* \
	      %{_rundir}/%{base_path}/status/* \
	      %{_localstatedir}/spool/%{base_path}/crons/* \
	      %{_localstatedir}/spool/%{base_path}/crons/*/* \
	      %{_localstatedir}/spool/%{base_path}/data/*/* \
	      1>/dev/null 2>&1
fi
exit 0

%postun -n ripe-atlas-common
%systemd_postun_with_restart %{service_name}
exit 0

%postun -n ripe-atlas-probe
%systemd_postun_with_restart %{service_name}
exit 0
