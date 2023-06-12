%define     git_repo         ripe-atlas-software-probe
%define     build_dirname    %{git_repo}
%define     base_path        ripe-atlas
%define     src_prefix_dir   /usr/local/ripe-atlas
%define     service_name     ripe-atlas.service
%define     version          %(find . -name VERSION | head -1 | xargs -I {} sh -c "cat {}")

# define user to perform measurements
%define     msm_user         ripe-atlas
%define     msm_group        ripe-atlas
%define     msm_homedir      %{_localstatedir}

# flag to ignore files installed in builddir but not packaged in the final RPM
%define	    _unpackaged_files_terminate_build	0

# prevent creation of the build ids in /usr/lib -> see https://access.redhat.com/discussions/5045161
%define	    _build_id_links none

# transition directory key storage
%define	    key_dirname	/var/tmp/ripe-atlas-keydir

Name:	    	ripe-atlas-common
Summary:    	RIPE Atlas probe
Version:    	%{version}
Release:    	1%{?dist}
License:    	RIPE NCC
Group:      	Applications/Internet
Requires:   	sudo %{?el6:daemontools} %{?el7:psmisc} %{?el8:psmisc} openssh-clients iproute %{?el7:sysvinit-tools} %{?el8:procps-ng} net-tools hostname
BuildRequires:	rpm %{?el7:systemd} %{?el8:systemd} openssl-devel autoconf automake libtool make

%description
Essential core assets used in all probe flavours. This package must be installed for a probe to operate as expected.

%package -n ripe-atlas-probe
Summary:	RIPE Atlas Probe Software Essentials
Group:		Applications/Internet
BuildArch:      noarch 
Provides:	atlasswprobe = %{version}-%{release}
Obsoletes:	atlasswprobe < 5080-3%{?dist}
Requires:	ripe-atlas-common = %{version}-%{release}

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
./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --localstatedir=%{_localstatedir} --libdir=%{_libdir}
make

%install
cd %{_builddir}/%{build_dirname}
mkdir -p %{buildroot}%{_unitdir}
install -m644 %{_builddir}/%{build_dirname}/bin/%{service_name} %{buildroot}%{_unitdir}/%{service_name}
mkdir -p %{buildroot}%{_datadir}/%{base_path}
install -m644 %{_builddir}/%{build_dirname}/atlas-config/probe/known_hosts.reg %{buildroot}%{_datadir}/%{base_path}/known_hosts.reg
mkdir -p %{buildroot}%{_libexecdir}/%{base_path}/scripts
install -m644 %{_builddir}/%{build_dirname}/atlas-config/probe/reg_servers.sh.prod %{buildroot}%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod
make DESTDIR=%{buildroot} install

%files
%exclude %dir %{_sbindir}
%{_sbindir}/ripe-atlas
%{_libexecdir}
%{_localstatedir}
%{_sysconfdir}
%{_unitdir}/%{service_name}
%{_datadir}/%{base_path}/FIRMWARE_APPS_VERSION
%caps(cap_net_raw=ep) %attr(0750, ripe-atlas, ripe-atlas) %{_libexecdir}/%{base_path}/measurement/busybox

%files -n ripe-atlas-probe
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod

%pre -n ripe-atlas-common
systemctl stop %{service_name} 2>&1 1>/dev/null

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
fi

# clean environment
killall -9 eooqd eperd perd telnetd 2>/dev/null || :
rm -fr %{_rundir}/%{base_path}/status/* %{_libexecdir}/%{base_path}/scripts/reg_servers.sh

# add measurement system group
if [ ! $(getent group %{msm_group}) ]; then
	groupadd %{msm_group}
fi

# init measurement user
GID=$(getent group %{msm_group} | cut -d: -f3)
useradd -c %{msm_user} -d %{_localstatedir} -g %{msm_group} -s /sbin/nologin -u $GID %{msm_group} 2>/dev/null
exit 0


%post -n ripe-atlas-probe
# set to environment
if [ ! -f %{_sysconfdir}/%{base_path}/mode ]; then
    %{!?env:%define env prod}
    echo %{env} > %{_sysconfdir}/%{base_path}/mode
fi

# apply permissions
chown -R %{msm_user}:%{msm_group} %{buildroot}%{_localstatedir}/spool/%{base_path}
chown -R %{msm_user}:%{msm_group} %{buildroot}%{_localstatedir}/run/%{base_path}/{pids,status}

%systemd_post %{service_name}
systemctl restart %{service_name}
exit 0


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
