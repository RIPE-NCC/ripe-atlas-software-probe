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

%changelog
* Wed Aug 9 2023 Michel Stam <mstam@ripe.net>
- Refactor anchor build spec according to probe spec

* Mon Dec 19 2022 Guy Meyer <gmeyer@ripe.net>
- generalize system and msm users
- do not remove probe private key on uninstall
- convert to noarch
- add key preservation
- add deploy env variability

* Tue Nov 29 2022 Guy Meyer <gmeyer@ripe.net>
- rename package to atlas-anchor (obseletes for version 5080-1 , or older)
- rename this spec file: atlasprobe.spec.in -> atlas-anchor.spec
- add command line "--define" options for specific builds with "git_tag", "git_source" and "git_commit"
- add anchor-specific configurations to config.sh file during post-installation
- cleanup spec file, comments, add defines for generalizations

* Wed Oct 19 2022 Guy Meyer <gmeyer@ripe.net>
- add atlasswprobe as runtime dependency
- simplify script to include only anchor related functionality

* Wed Oct 5 2022 Guy Meyer <gmeyer@ripe.net>
- added support for el9

* Thu Jul 6 2017 Anand Buddhdev <anandb@ripe.net>
- Updated the SPEC file to build for both CentOS 6 and 7

* Thu Mar 28 2013 Anand Buddhdev <anandb@ripe.net>
- Removed some redundant kill commands, because the upstart script takes care of that
- Added code to the post-stop hook in the upstart script to delete all PID files
* Wed Mar 27 2013 Anand Buddhdev <anandb@ripe.net>
- Embedded the upstart script into the spec file; switched from "su" to "setuidgid"
- Added a post-stop hook to the upstart script to kill all atlas child processes
- Fixed a typo in the "stop on" stanza in the upstart script
- Added shell code to the the pre-install and pre-uninstall hooks to kill atlas child processes
- Added dependency on daemontools for setuidgid
- Some misc clean-ups in the spec file itself
- Removed the "setcap" call in the post-install hook; the capability is set by RPM itself
* Thu Jan 31 2013 Philip Homburg <phomburg@ripe.net>
- First real release
* Wed Oct 17 2012 Anand Buddhdev <anandb@ripe.net>
- First version of spec file
