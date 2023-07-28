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
%define	    key_dirname	/var/tmp/ripe-atlas-keydir

# Keep scripts intact
%define     __brp_mangle_shebangs_exclude_from ^%{_libexecdir}/%{base_path}/scripts/.*$

Name:	    	ripe-atlas-common
Summary:    	RIPE Atlas probe
Version:    	%{version}
Release:    	1%{?dist}
License:    	RIPE NCC
Group:      	Applications/Internet
Requires:   	%{?el6:daemontools} %{?el7:psmisc} %{?el8:psmisc} openssh-clients iproute %{?el7:sysvinit-tools} %{?el8:procps-ng} net-tools hostname
BuildRequires:	rpm systemd systemd-rpm-macros %{?el7:systemd} %{?el8:systemd} openssl-devel autoconf automake libtool make
URL:            https://atlas.ripe.net/

%description
Essential core assets used in all probe flavours. This package must be installed for a probe to operate as expected.

%package -n ripe-atlas-probe
Summary:	RIPE Atlas Probe Software Essentials
Group:		Applications/Internet
BuildArch:      noarch 
Provides:	atlasswprobe = %{version}-%{release}
Obsoletes:	atlasswprobe < 5080-3%{?dist}
Requires:	ripe-atlas-common = %{version}-%{release}
URL:            https://atlas.ripe.net/

%description -n ripe-atlas-probe
Probe specific files and configurations that form a working software probe.

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
./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --localstatedir=%{_localstatedir} --libdir=%{_libdir} --runstatedir=%{_rundir} --with-user=%{atlas_user} --with-group=%{atlas_group} --with-measurement-user=%{atlas_measurement} --enable-systemd --disable-chown --disable-setcap-install
make

%install
cd %{_builddir}/%{build_dirname}
make DESTDIR=%{buildroot} install

%files
%exclude %dir %{_sbindir}
%exclude %{_libexecdir}/%{base_path}/scripts/reg_servers.sh.*
%{_sbindir}/*
%{_libexecdir}/%{base_path}/scripts/*.sh
%dir %{_libexecdir}/%{base_path}/scripts
%{_libexecdir}/%{base_path}/scripts/resolvconf
%{_unitdir}/%{service_name}
%{_sysusersdir}/ripe-atlas.conf
%{_datadir}/%{base_path}
%{_tmpfilesdir}/ripe-atlas.conf
%{_sysconfdir}/%{base_path}/mode
%attr(0770, %{atlas_user}, %{atlas_group}) %dir %{_sysconfdir}/%{base_path}
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
%ghost %{_localstatedir}/%{base_path}
%caps(cap_net_raw=ep) %attr(4750, %{atlas_measurement}, %{atlas_group}) %{_libexecdir}/%{base_path}/measurement/busybox
%attr(2775, %{atlas_measurement}, %{atlas_group}) %{_localstatedir}/spool/%{base_path}

%files -n ripe-atlas-probe
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod

%pre -n ripe-atlas-common
systemctl stop %{service_name} 1>/dev/null 2>&1
%sysusers_create_package ripe-atlas %{_builddir}/%{build_dirname}/atlas-config/common/ripe-atlas.users.conf

# save probe keys
if [ -d /var/atlas-probe ]; then
	mkdir -p %{key_dirname}
	cp /var/atlas-probe/etc/probe_key* %{key_dirname}/
fi
exit 0

%pre -n ripe-atlas-probe
# TODO: check cgroup and that all processes are stopped when %{service_name} stops

# save files if not there already there and same - transitional
if [ ! -e %{key_dirname}/probe_key ] || [ -e /var/atlas-probe/etc/probe_key ] || ! $(cmp -s /var/atlas-probe/etc/probe_key %{key_dirname}/probe_key); then
	mkdir -p %{key_dirname}
	cp /var/atlas-probe/etc/probe_key* %{key_dirname}/
fi

# move in keys from obsolete package - transitional
if [ -e %{key_dirname}/probe_key ]; then
	mkdir -p %{_sysconfdir}/%{base_path}
	mv -f %{key_dirname}/probe_key* %{_sysconfdir}/%{base_path}/
	chown -R %{atlas_user}:%{atlas_group} %{_sysconfdir}/%{base_path}/probe_key*
fi

# clean environment
killall -9 eooqd eperd perd telnetd 2>/dev/null || :
rm -fr %{_rundir}/%{base_path}/status/* %{_libexecdir}/%{base_path}/scripts/reg_servers.sh
exit 0

%systemd_post %{service_name}
systemctl restart %{service_name} 1>/dev/null 2>&1
exit 0

%post -n ripe-atlas-common
%tmpfiles_create %{_tmpfilesdir}/ripe-atlas.conf

%preun -n ripe-atlas-common
# save probe keys
if [ ! -f %{key_dirname}/probe_key ]; then
	mkdir -p %{key_dirname}
	cp %{_localstatedir}/etc/probe_key* %{key_dirname}/
fi
exit 0


%preun -n ripe-atlas-probe
# save probe keys
if [ ! -f %{key_dirname}/probe_key ]; then
	mkdir -p %{key_dirname}
	cp %{_sysconfdir}/%{base_path}/probe_key* %{key_dirname}/
fi
exit 0


%postun -n ripe-atlas-probe
%systemd_postun %{service_name}
exit 0
