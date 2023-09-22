%define     git_repo         ripe-atlas-software-probe
%define     build_dirname    %{git_repo}
%define     base_path        ripe-atlas
%define     service_name     ripe-atlas.service
%define     version          %(find . -name VERSION | head -1 | xargs -I {} sh -c "cat {}")

# flag to ignore files installed in builddir but not packaged in the final RPM
%define	    _unpackaged_files_terminate_build	0

# prevent creation of the build ids in /usr/lib -> see https://access.redhat.com/discussions/5045161
%define	    _build_id_links none

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
install -m644 %{_builddir}/%{build_dirname}/config/anchor/known_hosts.reg %{buildroot}%{_datadir}/%{base_path}/known_hosts.reg
mkdir -p %{buildroot}%{_libexecdir}/%{base_path}/scripts
install -m644 %{_builddir}/%{build_dirname}/config/anchor/reg_servers.sh.prod %{buildroot}%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod

%files
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod
%ghost %{_sysconfdir}/%{base_path}/reg_servers.sh

%post
# clean environment; systemd should restart after this on upgrade
rm -fr %{_rundir}/%{base_path}/status/* %{_libexecdir}/%{base_path}/scripts/reg_servers.sh
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
