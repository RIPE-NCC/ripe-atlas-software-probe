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
%define     atlas_olddir       /home/atlas
%define     atlas_oldkey       %{atlas_olddir}/etc/probe_key
%define     atlas_oldmode      %{atlas_olddir}/state/mode
%define     atlas_oldconfig    %{atlas_olddir}/state/config.txt
%define     atlas_newdir       %{_sysconfdir}/%{base_path}
%define     atlas_newkey       %{atlas_newdir}/probe_key
%define     atlas_newmode      %{atlas_newdir}/mode
%define     atlas_newconfig    %{atlas_newdir}/config.txt

# Workaround for systems using autoconf 2.69 and older
%if 0%{?rhel} >= 9
%define     fix_rundir         %{_rundir}
%else
%define     fix_rundir         %{_localstatedir}/run
%endif

# Keep scripts intact
%define     __brp_mangle_shebangs_exclude_from ^%{_libexecdir}/%{base_path}/scripts/.*$

Name:           ripe-atlas-anchor
Summary:        RIPE Atlas Anchor Package
Version:        %{version}
Release:        1%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
BuildArch:      noarch
Requires:       ripe-atlas-common = %{version}-%{release}
BuildRequires:  rpm, systemd, openssl-devel
Provides:       atlasprobe = %{version}-%{release}
Obsoletes:      atlasprobe < 5080.0-3
Conflicts:      atlasprobe
URL:            https://atlas.ripe.net/anchors/apply/
%{systemd_requires}

%description
Probe specific files and configurations that form a working anchor. Please visit https://atlas.ripe.net/anchors/apply/ to register.
Only install at the direction of RIPE NCC.

%prep
echo "Building for anchor version: %{version}"

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

%install
mkdir -p %{buildroot}%{_datadir}/%{base_path}
install -m 0644 %{_builddir}/%{build_dirname}/config/anchor/known_hosts.reg %{buildroot}%{_datadir}/%{base_path}/known_hosts.reg
mkdir -p %{buildroot}%{_libexecdir}/%{base_path}/scripts
install -m 0755 %{_builddir}/%{build_dirname}/config/common/reg_servers.sh.dev %{buildroot}%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.dev
install -m 0755 %{_builddir}/%{build_dirname}/config/common/reg_servers.sh.test %{buildroot}%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.test
install -m 0755 %{_builddir}/%{build_dirname}/config/anchor/reg_servers.sh.prod %{buildroot}%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod

%files
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.*
%ghost %{_sysconfdir}/%{base_path}/reg_servers.sh

%define migrate_file() \
if ( [ -f "%1" ] && ! cmp -s "%1" "%2" 1>/dev/null 2>&1 ); then \
	install -D -p -m "%3" -o "%4" -g "%5" "%1" "%2" 1>/dev/null 2>&1; \
fi \
%{nil}

%post
# Migrate configuration files
%migrate_file %{atlas_oldkey}     %{atlas_newkey}     0400 %{atlas_user} %{atlas_group}
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
exit 0

%preun
# Uninstall
if [ $1 -eq 0 ]; then
	systemctl stop %{service_name} 1>/dev/null 2>&1
	systemctl disable %{service_name} 1>/dev/null 2>&1
fi
exit 0

%postun
%systemd_postun_with_restart %{service_name}
exit 0

%include rhel/changelog
