%define     git_repo         ripe-atlas-software-probe
%define     build_dirname    %{git_repo}
%define     local_state_dir  /home/ripe-atlas
%define     src_prefix_dir   /usr/local/ripe-atlas
%define     service_name     ripe-atlas.service
%define     version          %(find . -name VERSION | head -1 | xargs -I {} sh -c "cat {}")

# define user to perform measurements
%define     msm_user         ripe-atlas
%define     msm_group        ripe-atlas
%define     msm_homedir      %{local_state_dir}

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
./configure --prefix=%{src_prefix_dir} --localstatedir=%{local_state_dir}
make

%install
cd %{_builddir}/%{build_dirname}
mkdir -p %{buildroot}%{_unitdir}
install -m644 %{_builddir}/%{build_dirname}/bin/%{service_name} %{buildroot}%{_unitdir}/%{service_name}
make DESTDIR=%{buildroot} install

%clean
#rm -rf %{buildroot}%{src_prefix_dir}/include
#rm -rf %{buildroot}%{src_prefix_dir}/bin/%{service_name}
#rm -rf %{_builddir}

%files
%ghost %{src_prefix_dir}/bin/event_rpcgen.py
%ghost %{src_prefix_dir}/include/*
%ghost %{src_prefix_dir}/lib/pkgconfig
%{src_prefix_dir}/bb-13.3
%{src_prefix_dir}/bin/arch
%attr(755, root, root) %{src_prefix_dir}/bin/ATLAS
%attr(755, root, root) %{src_prefix_dir}/bin/reginit.sh
%attr(644, root, root) %{src_prefix_dir}/bin/common-pre.sh
%attr(644, root, root) %{src_prefix_dir}/bin/common.sh
%attr(755, root, root) %{src_prefix_dir}/bin/*.lib.sh
%attr(755, root, root) %{src_prefix_dir}/lib/libevent-2.1.so.7
%attr(755, root, root) %{src_prefix_dir}/lib/libevent-2.1.so.7.0.0
%attr(755, root, root) %{src_prefix_dir}/lib/libevent_openssl-2.1.so.7
%attr(755, root, root) %{src_prefix_dir}/lib/libevent_openssl-2.1.so.7.0.0
%caps(cap_net_raw=ep) %{src_prefix_dir}/bb-13.3/bin/busybox

%files -n ripe-atlas-probe
%attr(644, root, root) %{_unitdir}/%{service_name}
%{src_prefix_dir}/state
%{src_prefix_dir}/etc


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
	mkdir -p %{local_state_dir}/etc/
	mv -f %{key_dirname}/probe_key* %{local_state_dir}/etc/
fi

# clean environment
killall -9 eooqd eperd perd telnetd 2>/dev/null || :
rm -fr %{local_state_dir}/status %{local_state_dir}/bin/reg_servers.sh

# add measurement system group
if [ ! $(getent group %{msm_group}) ]; then
	groupadd %{msm_group}
fi

# init measurement user
GID=$(getent group ripe-atlas | cut -d: -f3)
useradd -c %{msm_user} -d %{local_state_dir} -g %{msm_group} -s /sbin/nologin -u $GID %{msm_group} 2>/dev/null
exit 0


%post -n ripe-atlas-probe
#exec 1>/tmp/ripe-atlas.out 2>/tmp/ripe-atlas.err
#set -x

# set to environment
if [ ! -f %{local_state_dir}/state/mode ]; then
    %{!?env:%define env prod}
    mkdir -p %{local_state_dir}/state
    echo %{env} > %{local_state_dir}/state/mode
fi

# create file structure hierarchy used for runtime data
mkdir -p %{local_state_dir}/{bin,crons/{main,2,7},data/{new,oneoff,out/ooq,out/ooq10},run}

# this file is likely no longer needed since the move to generic
cat > %{local_state_dir}/bin/config.sh << EOF
DEVICE_NAME=centos-sw-probe
ATLAS_BASE="%{local_state_dir}"
ATLAS_STATIC="%{src_prefix_dir}"
SUB_ARCH="centos-rpm-%{name}-%{version}-%{release}"
EOF

# pass runtime dir ownership to measurements user
chown -R %{msm_user}:%{msm_group} %{local_state_dir}
find %{local_state_dir} -type d -exec chmod -R 755 {} +
find %{local_state_dir} -type f -exec chmod -R 644 {} +
chmod 600 %{local_state_dir}/etc/probe_key

%systemd_post %{service_name}
exit 0


%preun -n ripe-atlas-common
# save probe keys
if [ ! -f %{key_dirname}/probe_key ]; then
	mkdir -p %{key_dirname}
	cp %{local_state_dir}/etc/probe_key* %{key_dirname}/
fi
exit 0


%preun -n ripe-atlas-probe
# save probe keys
if [ ! -f %{key_dirname}/probe_key ]; then
	mkdir -p %{key_dirname}
	cp %{local_state_dir}/etc/probe_key* %{key_dirname}/
fi
exit 0


%postun -n ripe-atlas-probe
%systemd_postun %{service_name}
exit 0
