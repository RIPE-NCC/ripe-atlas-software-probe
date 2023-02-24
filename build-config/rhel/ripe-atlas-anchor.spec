%define         git_repo	ripe-atlas-software-probe
%define         build_dirname	%{git_repo}
%define         base_path       ripe-atlas
%define		service_name	ripe-atlas.service
%define		version		%(find . -name VERSION | head -1 | xargs -I {} sh -c "cat {}")

# define user to perform connectivity operations to infra
%define     system_user         ripe-atlas
%define     system_group        ripe-atlas
%define     system_homedir      /home/ripe-atlas
%define     system_gid          10042

# define user to perform measurements
%define     msm_user         atlasmsm
%define     msm_group        atlasmsm
%define     msm_homedir      /home/atlasmsm
%define     msm_gid          10624

# transition directory key storage
%define     key_dirname /var/tmp/ripe-atlas-keydir

Name:           ripe-atlas-anchor
Summary:        RIPE Atlas Anchor Package
Version:        %{version}
Release:        1%{?dist}
License:        RIPE NCC
Group:          Applications/Internet
BuildArch:	noarch
Requires:       ripe-atlas-common = %{version}-%{release}
BuildRequires:  rpm, systemd, openssl-devel
Provides:	atlasprobe = %{version}-%{release}
Obsoletes:	atlasprobe < 5080.0-3
Conflicts:	atlasprobe

%description
Setup the RIPE Atlas Anchor Package

%prep
# performing the steps of '%setup' manually since we are pulling from a remote git repo
echo "Cleaning build dir"
cd %{_builddir}
rm -rf %{_builddir}/%{build_dirname}
echo "Getting Sources..."

%{!?git_tag:%define git_tag master}
%{!?git_source:%define git_source https://github.com/RIPE_NCC}

git clone -b %{git_tag} %{git_source}/%{git_repo}.git %{_builddir}/%{build_dirname}

cd %{_builddir}/%{build_dirname}
%{?git_commit:git checkout %{git_commit}}

%install
mkdir -p %{buildroot}%{_datadir}/%{base_path}
install -m644 --group=%{system_group} --owner=%{system_user} %{_builddir}/%{build_dirname}/atlas-config/anchor/known_hosts.reg %{buildroot}%{_datadir}/%{base_path}/known_hosts.reg
mkdir -p %{buildroot}%{_libexecdir}/%{base_path}/scripts
install -m644 --group=%{system_group} --owner=%{system_user} %{_builddir}/%{build_dirname}/atlas-config/anchor/reg_servers.sh.prod %{buildroot}%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod

%files
%{_datadir}/%{base_path}/known_hosts.reg
%{_libexecdir}/%{base_path}/scripts/reg_servers.sh.prod

%pre
systemctl stop %{service_name} &>/dev/null
killall -9 eooqd eperd perd telnetd 2>/dev/null || :

# save files if not there already there and same - transitional
# intentionally using full path of obsoleting key
if [ ! -e %{key_dirname}/probe_key ] || ! $(cmp -s /home/atlas/etc/probe_key %{key_dirname}/probe_key); then
        mkdir -p %{key_dirname}
        cp /home/atlas/etc/probe_key* %{key_dirname}/
fi

# remove cached files
rm -fr %{_rundir}/%{base_path}/status/* %{_libexecdir}/%{base_path}/scripts/reg_servers.sh

groupadd -g %{system_gid} %{system_user} 2>/dev/null
useradd -c %{system_user} -g %{system_group} -s /sbin/nologin -u %{system_gid} %{system_user} 2>/dev/null
groupadd -g %{msm_gid} %{msm_user} 2>/dev/null
useradd -c %{msm_user} -g %{msm_group} -s /sbin/nologin -u %{msm_gid} %{msm_user} 2>/dev/null
exit 0

%post
# move in keys from obsolete package - transitional
if [ -e %{key_dirname}/probe_key ]; then
        mkdir -p %{_sysconfdir}/%{base_path}
        mv -f %{key_dirname}/probe_key* %{_sysconfdir}/%{base_path}
        rmdir %{key_dirname}
fi

# set to environment
if [ ! -f %{_sysconfdir}/%{base_path}/mode ]; then
    %{!?env:%define env prod}
    echo %{env} > %{_sysconfdir}/%{base_path}/mode
fi

# apply permissions
chown -R %{msm_user}:%{msm_group} %{buildroot}%{_localstatedir}/spool/%{base_path}
chown -R %{msm_user}:%{msm_group} %{buildroot}%{_localstatedir}/run/%{base_path}/pids
chown -R %{system_user}:%{system_user} %{buildroot}%{_localstatedir}/run/%{base_path}/status

# start service
%systemd_post %{service_name}
systemctl --now --quiet enable %{service_name}

# lock ssh files to stop obsoleting package from deleting them - transitional
chattr +i /home/atlas/etc/probe_key*
exit 0

%preun
# stop and disable
%systemd_preun %{service_name}
exit 0

%postun
%systemd_postun %{service_name}
exit 0

%changelog
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
